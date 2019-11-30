#!/usr/bin/python

import uuid
import os
import sys
import glob
import json
import ldap
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

ces_dir = os.path.join('/tmp', str(uuid.uuid4()).split('-')[0])

ces_zip = '/opt/dist/gluu/community-edition-setup.zip'
cmd = 'unzip -q {} -d {}'.format(ces_zip, ces_dir)


for l in open('/etc/gluu/conf/gluu-ldap.properties'):
    if l.startswith('bindPassword'):
        crypted_passwd = l.split(':')[1].strip()
        ldap_password = os.popen('/opt/gluu/bin/encode.py -D {}'.format(crypted_passwd)).read().strip()
    elif l.startswith('servers'):
        ls = l.strip()
        n = ls.find(':')
        s = ls[n+1:].strip()
        servers_s = s.split(',')
        ldap_server = servers_s[0].strip()
    elif l.startswith('bindDN'):
        ldap_binddn = l.split(':')[1].strip()


######### LDAP ENTRY CHANGES #########

ldap_conn = ldap.initialize('ldaps://'+ldap_server)
ldap_conn.simple_bind_s(ldap_binddn, ldap_password)


#Move value of oxAuthClientSecretExpiresAt to oxAuthExpiration in clients entries
client_results = ldap_conn.search_s('ou=clients,o=gluu',ldap.SCOPE_SUBTREE,'(objectclass=oxAuthClient)',['oxAuthClientSecretExpiresAt'])
for client in client_results:
    if 'oxAuthClientSecretExpiresAt' in client[1]:
        oxAuthExpiration = client[1]['oxAuthClientSecretExpiresAt']
        base_dn = client[0]
        if 'oxAuthExpiration' in  client[1]:
            ldap_conn.modify_s(base_dn, [(ldap.MOD_DELETE, 'oxAuthExpiration', None)])
        ldap_conn.modify_s(base_dn, [(ldap.MOD_ADD, 'oxAuthExpiration',  oxAuthExpiration)])
        ldap_conn.modify_s(base_dn, [(ldap.MOD_DELETE, 'oxAuthClientSecretExpiresAt', None)])

#Increase value of defaultCleanupBatchSize in oxCacheConfiguration for nativePersistenceConfiguration to 10 mins
oxCacheConfiguration_ldap_result = ldap_conn.search_s('ou=configuration,o=gluu',ldap.SCOPE_SUBTREE,'(objectclass=gluuConfiguration)',['oxCacheConfiguration'])
oxCacheConfiguration_base_dn = oxCacheConfiguration_ldap_result[0][0]
oxCacheConfiguration_json = oxCacheConfiguration_ldap_result[0][1]['oxCacheConfiguration'][0]
oxCacheConfiguration = json.loads(oxCacheConfiguration_json)
oxCacheConfiguration['nativePersistenceConfiguration']['defaultCleanupBatchSize'] = 10000
oxCacheConfiguration_json = json.dumps(oxCacheConfiguration, indent=2)
ldap_conn.modify_s(oxCacheConfiguration_base_dn, [(ldap.MOD_REPLACE, 'oxCacheConfiguration',  oxCacheConfiguration_json)])

#Change clean up interval to 60 seconds and limit to 10000 in oxAuthConfDynamic
oxAuthConfDynamic_ldap_result = ldap_conn.search_s('ou=oxauth,ou=configuration,o=gluu',ldap.SCOPE_SUBTREE,'(objectclass=oxAuthConfiguration)',['oxAuthConfDynamic'])
oxAuthConfDynamic_base_dn = oxAuthConfDynamic_ldap_result[0][0]
oxAuthConfDynamic_json = oxAuthConfDynamic_ldap_result[0][1]['oxAuthConfDynamic'][0]
oxAuthConfDynamic = json.loads(oxAuthConfDynamic_json)
oxAuthConfDynamic['cleanServiceInterval'] = 60
oxAuthConfDynamic['cleanServiceBatchChunkSize'] = 10000
oxAuthConfDynamic_json = json.dumps(oxAuthConfDynamic, indent=2)
ldap_conn.modify_s(oxAuthConfDynamic_base_dn, [(ldap.MOD_REPLACE, 'oxAuthConfDynamic',  oxAuthConfDynamic_json)])

######################################

sys.exit()

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
