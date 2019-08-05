#!/usr/bin/python

import os
import sys
import ssl
import httplib
import json
import re

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
        pass


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

    def update_casa(self):

        print "Downloading Casa"
        setupObject.run(['wget', '-nv', 'https://ox.gluu.org/maven/org/gluu/casa/{0}/casa-{0}.war'.format(self.current_version), '-O', os.path.join(setupObject.distGluuFolder, 'casa.war')])
        print "Downloading Twillo"
        setupObject.run(['wget', '-nv', 'http://central.maven.org/maven2/com/twilio/sdk/twilio/7.17.0/twilio-7.17.0.jar', '-O', os.path.join(setupObject.distGluuFolder, 'twilio-7.17.0.jar')])

        if os.path.exists(setupObject.casa_config):
            casa_conf = setupObject.readFile(setupObject.casa_config)
            casa_conf_js = json.loads(casa_conf)

            try:
                casa_conf_js['oxd_config'].pop('use_https_extension')
                casa_conf_js['oxd_config'].pop('client')
            except:
                pass

            casa_conf = json.dumps(casa_conf_js, indent=2)
            setupObject.writeFile(casa_conf_fn, casa_conf)

        jettyServiceOxAuthCustomLibsPath = os.path.join(setupObject.jetty_base, 'oxauth', 'custom', 'libs')
        casa_base = os.path.join(setupObject.jetty_base, 'casa', 'webapps')
        
        setupObject.run(['cp', '-f', os.path.join(setupObject.distGluuFolder, 'casa.war'), casa_base])
        setupObject.run(['chown', '-R', 'jetty:jetty', casa_base])
        setupObject.run(['cp', '-f', os.path.join(setupObject.distGluuFolder, 'twilio-7.17.0.jar') , jettyServiceOxAuthCustomLibsPath])
        setupObject.run(['chown', '-R', 'jetty:jetty', jettyServiceOxAuthCustomLibsPath])
        
        casa_python_libs = os.path.join(setupObject.distGluuFolder, 'python','casa','*')
        setupObject.run(['cp', '-f', casa_python_libs, '/opt/gluu/python/libs'])

        #Update Default Config
        tmp_config_fn = os.path.join(self.setup_dir, 'templates', 'jetty', 'casa')
        tmp_config = self.render_template(tmp_config_fn)
        setupObject.writeFile(target_fn, tmp_config)
                

if __name__ == '__main__':
    setup_install_dir = os.path.join(cur_dir,'setup')
    setupObject = Setup(setup_install_dir)
    
    updaterObj = casaUpdate()
    updaterObj.check_if_gluu_upgarded()
    #updaterObj.check_and_update_oxd()
    
