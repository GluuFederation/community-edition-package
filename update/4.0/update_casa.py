#!/usr/bin/python

import os
import sys
import ssl
import httplib
import json
import re
import glob
import time

cur_dir = os.path.dirname(os.path.realpath(__file__))
setup_dir = os.path.join(cur_dir, 'setup')

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
        self.current_version = '4.0.b1'
        
        if not os.path.exists(self.casa_config_fn):
            print "Casa config file {} was not found. Exiting ...".format(self.casa_config_fn)
            sys.exit()

        casa_conf = setupObject.readFile(self.casa_config_fn)
        self.casa_conf_js = json.loads(casa_conf)


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
                if check_oxd_server('localhost', 8443):
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

            oxd_port = 8443
            oxd_host = self.casa_conf_js['oxd_config']['host']
            
            if ':' in oxd_server_address:
                try:
                    oxd_host, oxd_port = oxd_server_address.split(':')
                except:
                    pass
            else:
                oxd_host = oxd_server_address.strip()

            if not check_oxd_server(oxd_host, oxd_port):
                print "oxd server {}:8443 health status seems not good. Please download".format(oxd_host,oxd_port)
                print "https://raw.githubusercontent.com/GluuFederation/oxd/version_4.0/upgrade/oxd_updater.py"
                print "on your oxd server and perform upgrade."
                return False
            
            self.casa_conf_js['oxd_config']['host'] = oxd_host
            self.casa_conf_js['oxd_config']['port'] = oxd_port
            
            print "oxd server seems good."
        
        return True

    def render_template(self, tmp_file):
        data_dict = setupObject.__dict__
        data_dict.update(setupObject.templateRenderingDict)
        
        ldif_temp = open(tmp_file).read()
        ldif_temp = setupObject.fomatWithDict(ldif_temp,  data_dict)
        
        return ldif_temp


    def update_casa(self):

        print "Downloading Casa"
        setupObject.run(['wget', '-nv', 'https://ox.gluu.org/maven/org/gluu/casa/{0}/casa-{0}.war'.format(self.current_version), '-O', os.path.join(setupObject.distGluuFolder, 'casa.war')])
        print "Downloading Twillo"
        setupObject.run(['wget', '-nv', 'http://central.maven.org/maven2/com/twilio/sdk/twilio/7.17.0/twilio-7.17.0.jar', '-O', os.path.join(setupObject.distGluuFolder, 'twilio-7.17.0.jar')])

        try:
            self.casa_conf_js['oxd_config'].pop('use_https_extension')
            self.casa_conf_js['oxd_config'].pop('client')
        except:
            pass

        jettyServiceOxAuthCustomLibsPath = os.path.join(setupObject.jetty_base, 'oxauth', 'custom', 'libs')
        casa_base = os.path.join(setupObject.jetty_base, 'casa', 'webapps')
        
        setupObject.run(['cp', '-f', os.path.join(setupObject.distGluuFolder, 'casa.war'), casa_base])
        setupObject.run(['chown', '-R', 'jetty:jetty', casa_base])
        setupObject.run(['cp', '-f', os.path.join(setupObject.distGluuFolder, 'twilio-7.17.0.jar') , jettyServiceOxAuthCustomLibsPath])
        setupObject.run(['chown', '-R', 'jetty:jetty', jettyServiceOxAuthCustomLibsPath])

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
        setupObject.writeFile(tmp_config, tmp_config)


        casa_plugins_dir = os.path.join(setupObject.jetty_base, 'casa', 'plugins')

        #since download links are not ready, I put dummy links
        plugin_upgrades = {'authorized-clients': 'https://ox.gluu.org/maven/org/gluu/casa/4.0.b2/',
                           'strong-authn-settings': 'https://ox.gluu.org/maven/org/gluu/casa/4.0.b2/',
                           'account-linking': 'https://ox.gluu.org/maven/org/gluu/casa/4.0.b2/',
                           }

        for plugin in self.casa_conf_js.get('plugins', []):

            if plugin['id'] in plugin_upgrades:
                plugin_fn = os.path.join(casa_plugins_dir, plugin['relativePath'])
                
                if os.path.exists(plugin_fn):
                    setupObject.run(['rm', '-f', plugin_fn])
                
                if plugin['state'] == 'STARTED':
                    setupObject.run(['wget', plugin_upgrades[plugin['id']], '-O', plugin_fn])
                    plugin['relativePath'] = os.path.basename(plugin_upgrades[plugin['id']])


        custom_page_dir = os.path.join(setupObject.jetty_base, 'oxauth', 'custom', 'pages')
        setupObject.backupFile(os.path.join(custom_page_dir, 'casa.xhtml'))
        setupObject.copyFile(os.path.join(cur_dir, 'casa', 'casa.xhtml'), custom_page_dir)

        lib_dir = os.path.join(setupObject.gluuOptPythonFolder, 'libs')
        
        for script in glob.glob(os.path.join(cur_dir, 'casa', 'pylib','*')):
            setupObject.copyFile(script, lib_dir)

        #write json config file
        casa_conf = json.dumps(self.casa_conf_js, indent=2)
        setupObject.writeFile(self.casa_config_fn, casa_conf)        


    def import_oxd_certificate2javatruststore(self):
        setupObject.logIt("Importing oxd certificate")
        
        oxd_cert = ssl.get_server_certificate((self.casa_conf_js['oxd_config']['host'], self.casa_conf_js['oxd_config']['port']))
        oxd_alias = 'oxd_' + self.casa_conf_js['oxd_config']['host'].replace('.','_')
        oxd_cert_tmp_fn = '/tmp/{}.crt'.format(oxd_alias)

        with open(oxd_cert_tmp_fn,'w') as w:
            w.write(oxd_cert)

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
    updaterObj.check_and_update_oxd()
    updaterObj.update_casa()
    updaterObj.import_oxd_certificate2javatruststore()
