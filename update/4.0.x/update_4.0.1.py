#!/usr/bin/python

import uuid
import os
import sys
import glob

ces_dir = os.path.join('/tmp', str(uuid.uuid4()).split('-')[0])

ces_zip = '/opt/dist/gluu/community-edition-setup.zip'
cmd = 'unzip -q {} -d {}'.format(ces_zip, ces_dir)
print "Unzipping community edition setup package with command:"
print cmd
os.system(cmd)

ces_base_path = os.path.join(ces_dir, os.listdir(ces_dir)[0])

open(os.path.join(ces_base_path,'__init__.py'),'w').close()

sys.path.insert(0, ces_base_path)

from setup import Setup

setup_install_dir = os.path.join(ces_base_path)

setupObject = Setup(setup_install_dir)

old_setup_dir = '/install/community-edition-setup'

setupObject.log = os.path.join(old_setup_dir, 'update.log')
setupObject.logError = os.path.join(old_setup_dir, 'update_error.log')

setup_properties_fn = os.path.join(old_setup_dir, 'setup.properties.last')

setupObject.load_properties(setup_properties_fn,
                                no_update = [
                                        'install_dir',
                                        'node_version',
                                        'jetty_version',
                                        'jetty_dist',
                                        'outputFolder',
                                        'templateFolder',
                                        'staticFolder',
                                        'openDjIndexJson',
                                        'openDjSchemaFolder',
                                        'openDjschemaFiles',
                                        'opendj_init_file',
                                        'opendj_service_centos7',
                                        'log',
                                        'logError',
                                        'passport_initd_script',
                                        'node_initd_script',
                                        'jre_version',
                                        'java_type',
                                        'jreDestinationPath',
                                        ]
                                )

print "Updating gluu schema"

setupObject.copyFile(
        os.path.join(ces_base_path, 'static/opendj/101-ox.ldif'),
        setupObject.openDjSchemaFolder
        )

for service in ('oxauth', 'identity', 'idp', 'oxauth-rp'):
    print "Updating", service
    if os.path.exists(os.path.join(setupObject.jetty_base, service)):
        setupObject.copyFile(os.path.join(setupObject.distGluuFolder, service + '.war'),
                            os.path.join(setupObject.jetty_base, service,'webapps')
                            )
        setupObject.run(['chown', 'jetty:jetty', os.path.join(setupObject.jetty_base, service,'webapps', service + '.war')])

        if service == 'idp':
            print "Updating saml libraries"
            setupObject.install_saml_libraries()

print "Updating key generator libraries"
for f in glob.glob(os.path.join(setupObject.jetty_user_home_lib,'*')):
    setupObject.run(['rm', '-f', f])

setupObject.prepare_openid_keys_generator()

if os.path.exists('/opt/shibboleth-idp'):
    print "Extracting shibboleth-idp libraries"
    setupObject.run([setupObject.cmd_jar, 'xf', setupObject.distGluuFolder + '/shibboleth-idp.jar'], '/opt')
    setupObject.removeDirs('/opt/META-INF')


print "\n** Please logout from container and restart Gluu Server ***\n"
