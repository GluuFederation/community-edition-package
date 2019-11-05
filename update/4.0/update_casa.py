#!/usr/bin/python

import os
import sys
import ssl
import httplib
import json
import re
import glob
import time

import xml.etree.ElementTree as ET

cur_dir = os.path.dirname(os.path.realpath(__file__))
setup_dir = os.path.join(cur_dir, 'setup')

if not os.path.exists('/opt/dist/gluu/oxauth.war'):
    print "Please run this script inside the Gluu container. Exiting..."
    sys.exit()


if not os.path.exists(setup_dir):
    print "setup directory does not exists. Please first run Gluu Server upgrader script. Exiting..."
    sys.exit()

setup_init = os.path.join(setup_dir, '__init__.py')

if not os.path.exists(setup_init):
    print "setup was not initialized. Please first run Gluu Server upgrader script. Exiting..."
    sys.exit()

from setup.pylib.printVersion import get_war_info
from setup.setup import Setup

from setup.pylib.Properties import Properties

import ldap
import ldap.modlist as modlist
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)


def check_oxd_server(host, port):
    conn = httplib.HTTPSConnection (host, port, context=ssl._create_unverified_context())
    
    try:
        conn.request ("GET", "/health-check")
        result = conn.getresponse()

        if result.status == 200:
            text = result.read()
            data = json.loads(text)
            if data['status'] == 'running':
                return True

    except:
        return False


class casaUpdate(object):
    
    def __init__(self):

        self.casa_config_fn = os.path.join(setupObject.configFolder, 'casa.json')
        self.current_version = '4.0.Final'
        self.oxd_port = 8443
        self.oxd_host = None

        self.rpm_package = 'https://repo.gluu.org/centos/7/gluu-casa-4.0-centos7.noarch.rpm'
        self.deb_package = 'https://repo.gluu.org/ubuntu/pool/main/xenial/gluu-casa_4.0~xenial_all.deb'


        if not os.path.exists(self.casa_config_fn):
            print "Casa config file {} was not found. Exiting ...".format(self.casa_config_fn)
            sys.exit()

        casa_conf = setupObject.readFile(self.get_first_backup(self.casa_config_fn))
        self.casa_conf_js = json.loads(casa_conf)

    def get_first_backup(self, fn):
        file_list = glob.glob(fn+'.gluu-{0}-*~'.format(setupObject.currentGluuVersion))

        if not file_list:
            return fn

        file_list.sort(key=lambda fn_: [ c for c in re.split(r'(\d+)', fn_) ])

        print "Using backed up file", file_list[0]

        return file_list[0]


    def check_if_gluu_upgarded(self):
        oxauth_info = get_war_info(os.path.join(setupObject.jetty_base, 'oxauth', 'webapps', 'oxauth.war'))
        self.oxVersion = oxauth_info['version']
        currentGluuVersion = re.search('([\d.]+)', oxauth_info['version']).group().strip('.')
        print "Detected oxAuth version is:",  currentGluuVersion
        if currentGluuVersion < '4.0':
            print "Gluu server was not upgraded. Please first run Gluu Server upgrader script. Exiting..."
            sys.exit()


    def check_and_update_oxd(self):
        if os.path.exists('/opt/oxd-server'):
            print "Local oxd installation is detected. Casa 4.0 depends on oxd 4.0."
            print "Checking if local oxd is up to date"
            if check_oxd_server('localhost', self.oxd_port):
                print "oxd server seems good. No need to update."
                return True

            upgrade_oxd = setupObject.getPrompt("Upgrade oxd now [y/N]", defaultValue='n')
            if upgrade_oxd and upgrade_oxd[0].lower() == 'y':
                print "Downloading oxd updater script"
                setupObject.run(['wget', '-nv', 'https://raw.githubusercontent.com/GluuFederation/oxd/version_4.0/upgrade/oxd_updater.py', '-O', 'oxd_updater.py'])
                print "Running oxd_updater.py"
                os.system('python oxd_updater.py')
                print "Restarting oxd server"
                setupObject.run_service_command('oxd-server', 'restart')
                #wait a couple of seconds
                time.sleep(2)
                print "Checking oxd server health"
                if check_oxd_server('localhost', self.oxd_port):
                    print "oxd server seems good."
                else:
                    print "oxd server health status seems not good. Please check oxd server."
                    return False
            else:
                return False
        else:
            print "Casa 4.0 depends on oxd 4.0. Checking if oxd server is up to date."

            prompt_default = '{}:8443'.format(self.casa_conf_js['oxd_config']['host'])
            oxd_server_address = setupObject.getPrompt("Enter oxd server and port", defaultValue=prompt_default)

            self.oxd_host = self.casa_conf_js['oxd_config']['host']
            
            if ':' in oxd_server_address:
                try:
                    self.oxd_host, self.oxd_port = oxd_server_address.split(':')
                except:
                    pass
            else:
                self.oxd_host = oxd_server_address.strip()

            if not check_oxd_server(self.oxd_host, self.oxd_port):
                print "oxd server {}:8443 health status seems not good. Please download".format(oxd_host,oxd_port)
                print "https://raw.githubusercontent.com/GluuFederation/oxd/version_4.0/upgrade/oxd_updater.py"
                print "on your oxd server and perform upgrade."
                return False

            print "oxd server seems good."
        
        return True

    def render_template(self, tmp_file):
        data_dict = setupObject.__dict__
        data_dict.update(setupObject.templateRenderingDict)
        
        ldif_temp = open(tmp_file).read()
        ldif_temp = setupObject.fomatWithDict(ldif_temp,  data_dict)
        
        return ldif_temp


    def download_extract_package(self):
    
        cwdir = os.path.join(cur_dir, 'temp')
        
    
        if setupObject.os_type in ('debian', 'ubuntu'):
            print "Downloading", self.deb_package
            self.casa_package = 'gluu-casa.deb'
            setupObject.run(['wget', '-nv', self.deb_package, '-O', os.path.join(cur_dir, 'temp', self.casa_package)])
            print "Extracting", self.deb_package
            setupObject.run(['dpkg', '-x', self.casa_package, cwdir], cwd=cwdir)
        else:
            print "Downloading", self.rpm_package
            self.casa_package = 'gluu-casa.rpm'
            setupObject.run(['wget', '-nv', self.rpm_package, '-O', os.path.join(cur_dir, 'temp', self.casa_package)])
            print "Extracting", self.rpm_package
            cmd = 'rpm2cpio {0} | cpio -idvm'.format(self.casa_package)
            setupObject.run([cmd], shell=True, cwd=cwdir)

    def update_casa(self):

        print "Updating Casa"
        
        print "Stopping Casa Service"
        setupObject.run_service_command('casa', 'stop')

        twilio_jar_fn = 'twilio-7.17.0.jar'

        for a in ('use_https_extension', 'client'):
            if a in self.casa_conf_js['oxd_config']:
                self.casa_conf_js['oxd_config'].pop(a)

        self.casa_conf_js['oxd_config']['port'] = self.oxd_port
        self.casa_conf_js['ldap_settings']['config_file'] = setupObject.ox_ldap_properties
        self.casa_conf_js['ldap_settings']['ox-ldap_location'] = None

        if self.oxd_host:
            self.casa_conf_js['oxd_config']['host'] = self.oxd_host

        jettyServiceOxAuthCustomLibsPath = os.path.join(setupObject.jetty_base, 'oxauth', 'custom', 'libs')
        casa_base = os.path.join(setupObject.jetty_base, 'casa', 'webapps')
        
        setupObject.run(['cp', '-f', os.path.join(cur_dir, 'temp/opt/gluu-server/opt/dist/gluu/casa.war'), casa_base])
        setupObject.run(['chown', '-R', 'jetty:jetty', casa_base])
        setupObject.run(['cp', '-f', os.path.join(cur_dir, 'temp/opt/gluu-server/opt/dist/gluu', twilio_jar_fn), jettyServiceOxAuthCustomLibsPath])
        setupObject.run(['chown', '-R', 'jetty:jetty', jettyServiceOxAuthCustomLibsPath])

        twilio_path = os.path.join(jettyServiceOxAuthCustomLibsPath, twilio_jar_fn)
        oxauth_fn = os.path.join(setupObject.jetty_base, 'oxauth/webapps/oxauth.xml')

        oxauth_fn_exists = os.path.exists(oxauth_fn)

        if not oxauth_fn_exists:
            setupObject.copyFile(
                        os.path.join(cur_dir, 'setup/templates/jetty/oxauth.xml'),
                        os.path.join(setupObject.jetty_base, 'oxauth/webapps')
                        )

        tree = ET.parse(oxauth_fn)
        root = tree.getroot()

        for Set in root.findall('Set'):
            if Set.get('name') == 'extraClasspath':
                if 'twilio' in Set.text:
                    Set.text = twilio_path
                    break
        else:
            child = ET.Element("Set", {'name':'extraClasspath'})
            child.text = twilio_path
            root.append(child)
    
        if oxauth_fn_exists:
            setupObject.backupFile(oxauth_fn)
    
        tree.write(oxauth_fn)
        setupObject.run(['chown', '-R', 'jetty:jetty', oxauth_fn])

        casa_default_fn = os.path.join(setupObject.osDefault, 'casa')
        setupObject.casa_min_heap_mem = '256'
        setupObject.casa_max_heap_mem = '716'
        setupObject.casa_max_meta_mem = '307'
        
        if os.path.exists(casa_default_fn):
            p=Properties()

            with open(casa_default_fn) as f:
                p.load(f)
    
            result = re.search('Xms(\d.*)m -Xmx(\d.*)m -XX:MaxMetaspaceSize=(\d.*)m', p['JAVA_OPTIONS'])

        if result:
            setupObject.casa_min_heap_mem, setupObject.casa_max_heap_mem, setupObject.casa_max_meta_mem = result.groups()


        #Update Default Config
        tmp_config_fn = os.path.join(setup_dir, 'templates', 'jetty', 'casa')
        tmp_config = self.render_template(tmp_config_fn)
        setupObject.writeFile(casa_default_fn, tmp_config)


        casa_plugins_dir = os.path.join(setupObject.jetty_base, 'casa', 'plugins')

        #since download links are not ready, I put dummy links
        plugin_upgrades = {
                            'authorized-clients': 'https://casa.gluu.org/wp-content/uploads/2019/10/authorized-clients-4.0.Final-jar-with-dependencies.jar',
                            'custom-branding': 'https://casa.gluu.org/wp-content/uploads/2019/10/custom-branding-4.0.Final-jar-with-dependencies.jar',
                            'strong-authn-settings': 'https://casa.gluu.org/wp-content/uploads/2019/10/strong-authn-settings-4.0.Final-jar-with-dependencies.jar',
                            'account-linking': 'https://casa.gluu.org/wp-content/uploads/2019/10/account-linking-4.0.Final-jar-with-dependencies.jar',
                            'inwebo-plugin': 'https://casa.gluu.org/wp-content/uploads/2019/10/inwebo-plugin-4.0.Final-jar-with-dependencies.jar.zip',
                           }

        casa_plugins = self.casa_conf_js.pop('plugins') if 'plugins' in self.casa_conf_js else []

        account_linking_src_dir = os.path.join(cur_dir, 'temp', 'opt/gluu-server/opt/dist/gluu/casa-al')

        for plugin in casa_plugins:

            if plugin['id'] in plugin_upgrades:
                plugin_fn = os.path.join(casa_plugins_dir, plugin['relativePath'])
                
                if os.path.exists(plugin_fn):
                    setupObject.run(['rm', '-f', plugin_fn])
                
                if plugin['state'] == 'STARTED':
                    new_plugin_fn = os.path.join(casa_plugins_dir, os.path.basename(plugin_upgrades[plugin['id']]))
                    print "Downloading", plugin_upgrades[plugin['id']]
                    setupObject.run(['wget', '-nv', plugin_upgrades[plugin['id']], '-O', new_plugin_fn])


                if plugin['id'] == 'account-linking':

                    setupObject.copyFile(os.path.join(account_linking_src_dir, 'casa.xhtml'), 
                                        os.path.join(setupObject.jetty_base, 'oxauth', 'custom', 'pages')
                                        )

                    print "Updating casa.py in ldap"

                    ldap_p=Properties()

                    with open(setupObject.ox_ldap_properties) as f:
                        ldap_p.load(f)

                    ldap_password = os.popen('/opt/gluu/bin/encode.py -D ' + ldap_p['bindPassword']).read().strip()

                    ldap_host = ldap_p['servers'].split(',')[0].strip()
                    ldap_uri = 'ldaps://{}'.format(ldap_host)
                    setupObject.logIt("Connecting ldap " + ldap_uri)
                    
                    ldap_conn = ldap.initialize(ldap_uri)
                    ldap_conn.simple_bind_s(ldap_p['bindDN'], ldap_password)
                    
                    result=ldap_conn.search_s('ou=scripts,o=gluu',ldap.SCOPE_SUBTREE,'(inum=BABA-CACA)')

                    if result:
                        setupObject.logIt("casa script entry in ldap found")
                        dn = result[0][0]
                        setupObject.logIt("dn of casa script: " + dn)
                        oxLevel = int(result[0][1]['oxLevel'][0]) + 1
                        oxScript = setupObject.readFile(
                                    os.path.join(account_linking_src_dir, 'casa.py')
                                    )

                        rm = ldap_conn.modify_s(dn, [
                                                ( ldap.MOD_REPLACE, 'oxLevel',  str(oxLevel)),
                                                ( ldap.MOD_REPLACE, 'oxScript',  oxScript),
                                                ]
                                            )
                        if rm:
                            setupObject.logIt("casa script updated")
                            print "Casa script in ldap was updated"
                    else:
                        setupObject.logIt("can't find casa script in ldap")

        lib_dir = os.path.join(setupObject.gluuOptPythonFolder, 'libs')

        for script in glob.glob(os.path.join(cur_dir, 'temp/opt/gluu-server/opt/gluu/python/libs/*')):
            setupObject.copyFile(script, lib_dir)

        #write json config file
        casa_conf = json.dumps(self.casa_conf_js, indent=2)
        setupObject.writeFile(self.casa_config_fn, casa_conf)        
    
        for setup_script in glob.glob( os.path.join(cur_dir, 'temp', 'opt/gluu-server/install/community-edition-setup/*.*')):
            setupObject.copyFile(setup_script, '/install/community-edition-setup')
    
        print "Removing temporary files"
        setupObject.run(['rm', '-f', os.path.join(cur_dir, 'temp', self.casa_package)])
        setupObject.run(['rm', '-r', '-f', os.path.join(cur_dir, 'temp/opt')])

        open(os.path.join(setupObject.jetty_base, 'casa/.administrable'), 'w').close()

        updaterObj.import_oxd_certificate2javatruststore()
        
        print "Starting Casa"
        setupObject.run_service_command('casa', 'start')

    def import_oxd_certificate2javatruststore(self):
        print "Importing oxd certificate"
        setupObject.logIt("Importing oxd certificate")
        
        oxd_cert = ssl.get_server_certificate((self.casa_conf_js['oxd_config']['host'], self.casa_conf_js['oxd_config']['port']))
        oxd_alias = 'oxd_' + self.casa_conf_js['oxd_config']['host'].replace('.','_')
        oxd_cert_tmp_fn = os.path.join(cur_dir, '{}.crt'.format(oxd_alias))

        setupObject.writeFile(oxd_cert_tmp_fn, oxd_cert)

        setupObject.run(['/opt/jre/jre/bin/keytool', '-import', '-trustcacerts', '-keystore', 
                        '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', 
                        '-noprompt', '-alias', oxd_alias, '-file', oxd_cert_tmp_fn])

if __name__ == '__main__':
    setup_dir = os.path.join(cur_dir,'setup')
    setupObject = Setup(setup_dir)
    setupObject.log = os.path.join(setup_dir, 'casa_update.log')
    setupObject.logError = os.path.join(setup_dir, 'casa_update_error.log')
    setupObject.os_initdaemon = setupObject.detect_initd()
    setupObject.os_type, setupObject.os_version = setupObject.detect_os_type()
    
    updaterObj = casaUpdate()
    updaterObj.check_if_gluu_upgarded()
    
    
    updaterObj.download_extract_package()
    
    if updaterObj.check_and_update_oxd():
        updaterObj.update_casa()
    else:
        print "Please fix oxd update and re-run this script. Exiting for now ..."

    print ("* Casa upgrade completed. Please restart gluu server before you\n"
           "  access the application.")
    print ("* You need a valid license for using this application.\n"
           "  To purchase a license please contact us -\n"
           "  https://www.gluu.org/company/contact-us")
