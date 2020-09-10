#!/usr/bin/python

import re
import os
import sys
import time
import json
import ldap
import pyDes
import base64
import ldap.modlist as modlist
import glob
import zipfile

cur_dir = os.path.dirname(os.path.realpath(__file__))
properties_password = None

if not os.path.exists('/etc/gluu/conf'):
    sys.exit('Please run this script inside Gluu container.')

from pyDes import *

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)


result = raw_input("Starting upgrade. CONTINUE? (y|N): ")
if not result.strip() or (result.strip() and result.strip().lower()[0] != 'y'):
    print "You can re-run this script to upgrade. Bye now ..."
    sys.exit()

def get_properties(prop_fn, current_properties=None):
    if not current_properties:
        p = Properties.Properties()
    else:
        p = current_properties

    with open(prop_fn) as file_object:
        p.load(file_object)
    
    for k in p.keys():
        if p[k].lower() == 'true':
            p[k] == True
        elif p[k].lower() == 'false':
            p[k] == False

    return p


with open("/etc/gluu/conf/salt") as f:
    salt_property = f.read().strip()
    key = salt_property.split("=")[1].strip()


def unobscure(s):
    cipher = pyDes.triple_des(key)
    decrypted = cipher.decrypt(base64.b64decode(s), padmode=pyDes.PAD_PKCS5)
    return decrypted


def flatten(k):
    return k.lower().replace('`','').replace(' ', '').replace('(','').replace(')','')

def make_key(l):
    return [ flatten(u'{}'.format(k)) for k in l ]

class GluuUpdater:
    def __init__(self):
        self.ces_dir = os.path.join(cur_dir, 'ces_current')
        self.up_version = '4.1.1'
        self.build_tag = '.Final'
        self.backup_time = time.strftime('%Y-%m-%d.%H:%M:%S')
        self.app_dir = os.path.join(cur_dir, 'app')
        self.persist_changes = { 'oxAuthConfDynamic': [

                        ('tokenEndpointAuthMethodsSupported', 'add', 'element', "tls_client_auth"),
                        ('tokenEndpointAuthMethodsSupported', 'add', 'element', "self_signed_tls_client_auth"),
                        ('spontaneousScopeLifetime', 'add', 'entry', 86400),
                        ('cleanServiceInterval', 'change', 'entry',  60),
                        ('cleanServiceBatchChunkSize', 'change', 'entry',  10000),
                        ('metricReporterEnabled', 'remove', 'entry', None),
                        ('useLocalCache', 'add', 'entry', True),
                    ],
    
                    'oxTrustConfApplication' : [
                            ('useLocalCache', 'add', 'entry', True),
                            ]
                }
                
        self.delete_from_configuration = ['gluuFreeDiskSpace', 'gluuFreeMemory', 'gluuFreeSwap', 'gluuGroupCount', 'gluuIpAddress', 'gluuPersonCount', 'gluuSystemUptime']

        self.scripts_inum = ['2DAF-BA90', '2FDB-CF02', 'D40C-1CA4', '09A0-93D7', '92F0-BF9E', '09A0-93D6', '2124-0CF1', '2DAF-BA91']

        self.casa_plugins = {
            'strong-authn-settings': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/strong-authn-settings/{0}{1}/strong-authn-settings-{0}{1}-jar-with-dependencies.jar',
            'account-linking': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/account-linking/{0}{1}/account-linking-{0}{1}-jar-with-dependencies.jar',
            'authorized-clients': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/authorized-clients/{0}{1}/authorized-clients-{0}{1}-jar-with-dependencies.jar',
            'custom-branding': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/custom-branding/{0}{1}/custom-branding-{0}{1}-jar-with-dependencies.jar',
            }

        if not os.path.exists(self.app_dir):
            os.mkdir(self.app_dir)

    def download_ces(self):
        
        if not os.path.exists(self.ces_dir):
            ces_url = 'https://github.com/GluuFederation/community-edition-setup/archive/version_{}.zip'.format(self.up_version)
            print "Downloading Community Edition Setup {}".format(self.up_version)
            target_fn = os.path.join(cur_dir, 'version_{}.zip'.format(self.up_version))
            os.system('wget -q {} -O {}'.format(ces_url, target_fn))
            print "Extracting CES package"
            os.system('unzip -o -qq {}'.format(target_fn))
            extracted_path = os.path.join(cur_dir, 'community-edition-setup-version_{}'.format(self.up_version))
            os.system('mv {} {}'.format(extracted_path, self.ces_dir))
            os.system('wget -nv https://raw.githubusercontent.com/GluuFederation/community-edition-setup/master/pylib/generate_properties.py -O {}'.format(os.path.join(self.ces_dir, 'pylib', 'generate_properties.py')))
            os.system('rm ' + target_fn)

        open(os.path.join(self.ces_dir, '__init__.py'),'w').close()
        sys.path.append('ces_current')

        global Properties
        from ces_current import setup
        from ces_current.pylib.cbm import CBM
        from ces_current.pylib import Properties
        from ces_current.pylib.generate_properties import generate_properties

        self.cbm_obj = CBM
        self.setup = setup
        self.setupObj = self.setup.Setup(self.ces_dir)
        self.setupObj.log = os.path.join(self.ces_dir, 'update.log')
        self.setupObj.logError = os.path.join(self.ces_dir, 'update_error.log')
        self.setup.attribDataTypes.startup(self.ces_dir)
        self.setupObj.os_type, self.setupObj.os_version = self.setupObj.detect_os_type()
        self.setupObj.os_initdaemon = self.setupObj.detect_initd()
        self.setupObj.properties_password = properties_password
        

        print "Collecting properties"
        self.setup_prop = generate_properties(True)
        
        if not 'oxtrust_admin_password' in self.setup_prop:
            self.setup_prop['oxtrust_admin_password'] = self.setup_prop['ldapPass']

        for setup_key in self.setup_prop:
            setattr(self.setupObj, setup_key, self.setup_prop[setup_key])

        self.setupObj.ldapCertFn = self.setupObj.opendj_cert_fn
        self.setupObj.ldapTrustStoreFn = self.setupObj.opendj_p12_fn

        self.setupObj.encode_passwords()
        

    def determine_persistence_type(self):
        self.cb_buckets = []
        self.user_location = 'ldap'
        gluu_prop = get_properties(self.setupObj.gluu_properties_fn)
        self.persistence_type = gluu_prop['persistence.type']
        self.default_storage = self.persistence_type

        if self.persistence_type == 'hybrid':
            hybrid_prop = get_properties(self.setupObj.gluu_hybrid_roperties)    
            self.default_storage = hybrid_prop['storage.default']

        if self.persistence_type == 'ldap':
            self.db_connection_ldap()
        elif self.persistence_type == 'couchbase':
            self.db_connection_couchbase()
            self.user_location = 'couchbase'
        elif self.persistence_type == 'hybrid':
            self.db_connection_ldap()
            self.db_connection_couchbase()
            if 'people' in hybrid_prop['storage.couchbase.mapping']:
                self.user_location = 'couchbase'
            

    def update_persistence_data(self):
        getattr(self, 'update_' + self.default_storage)()

    def checkRemoteSchema(self):

        s_base = 'cn=Subschema' if self.ldap_type == 'openldap' else 'cn=schema'
        
        result = self.conn.search_s(s_base,ldap.SCOPE_BASE,'(objectclass=*)',['objectClasses'])
        for obj_s in result[0][1]['objectClasses']:
            obj = ObjectClass(obj_s)
            if  'oxCacheEntity' in obj.names:
                return True

    def db_connection_couchbase(self):
        gluu_cb_prop = get_properties(self.setupObj.gluuCouchebaseProperties)
        cb_serevr = gluu_cb_prop['servers'].split(',')[0].strip()
        cb_admin = gluu_cb_prop['auth.userName']
        self.encoded_cb_password = gluu_cb_prop['auth.userPassword']
        cb_passwd = unobscure(self.encoded_cb_password)

        self.cbm = self.cbm_obj(cb_serevr, cb_admin, cb_passwd)

        for p in ('couchbase_hostname', 'couchebaseClusterAdmin', 
                    'encoded_cb_password',
                    'encoded_couchbaseTrustStorePass'):
            
            setattr(self.setupObj, p, self.setup_prop[p])

        gluu_cb_prop = get_properties(self.setupObj.gluuCouchebaseProperties)
        cb_passwd = gluu_cb_prop['auth.userPassword']
        self.setupObj.mappingLocations = self.setup_prop['mappingLocations']
        self.setupObj.encoded_cb_password = self.encoded_cb_password

        self.setupObj.couchbaseBuckets = [ b.strip() for b in gluu_cb_prop['buckets'].split(',') ]


    def drop_index(self, bucket, index_name):
        cmd = 'DROP INDEX `{}`.`{}` USING GSI'.format(bucket, index_name)
        print "Removing index", index_name
        self.cbm.exec_query(cmd)

    def add_index(self, bucket, ind):
        cmd, index_name = self.setupObj.couchbaseMakeIndex(bucket, ind)
        if 'defer_build' in cmd:
            if not bucket in self.new_cb_indexes:
                self.new_cb_indexes[bucket] = []
            self.new_cb_indexes[bucket].append(index_name)
        print "Executing", cmd
        self.cbm.exec_query(cmd)

    def cb_indexes(self):
        self.new_cb_indexes = {}
        new_index_json_fn = os.path.join(self.ces_dir, 'static/couchbase/index.json')
        new_indexes = json.loads(self.setupObj.readFile(new_index_json_fn))
        
        data_result = self.cbm.exec_query('SELECT * FROM system:indexes')
        current_indexes = data_result.json()['results']

        for inds in current_indexes:

            ind = inds['indexes']
            bucket = ind['keyspace_id']

            if bucket in new_indexes:
                new_bucket_indexes = new_indexes[bucket]
                if not 'condition' in ind:
                    for bind in new_indexes[bucket]['attributes']:
                        new_index_key = make_key(bind)
                        tmp_ = [flatten(k) for k in ind['index_key']]
                        if set(tmp_) == set(new_index_key):
                            # index exists
                            break
                    else:
                        self.drop_index(bucket, ind['name'])

                else:
                    tmp_ = [ flatten(k) for k in ind['index_key'] ]
                    for bind in new_indexes[bucket]['static']:
                        new_index_key = make_key(bind[0])
                        if set(tmp_) == set(new_index_key) and flatten(ind['condition']) == flatten(bind[1]):
                            # index exists
                            break
                    else:
                        self.drop_index(bucket, ind['name'])

        for bucket in self.setupObj.couchbaseBuckets:
            for ind in new_indexes[bucket]['attributes']:
                new_index_key = make_key(ind)
                for cur_inds in current_indexes:
                    cur_ind = cur_inds['indexes']
                    if (cur_ind['keyspace_id'] == bucket) and (not 'condition' in cur_ind):
                        tmp_ = make_key(cur_ind['index_key'])
                        if set(tmp_) == set(new_index_key):
                            # index exists
                            break
                else:
                    self.add_index(bucket, ind)

            for ind in new_indexes[bucket]['static']:
                new_index_key = make_key(ind[0])
                new_index_cond = flatten(ind[1])
                for cur_inds in current_indexes:
                    cur_ind = cur_inds['indexes']
                    if (cur_ind['keyspace_id'] == bucket) and ('condition' in cur_ind):
                        tmp_ = make_key(cur_ind['index_key'])
                        if set(tmp_) == set(new_index_key) and (flatten(cur_ind['condition']) == new_index_cond):
                            # "exists"
                            break
                else:
                    self.add_index(bucket, ind)

        for bucket in self.new_cb_indexes:
            cmd = 'BUILD INDEX ON `%s` (%s) USING GSI' % (bucket, ', '.join(self.new_cb_indexes[bucket]))
            print "Executing", cmd
            self.cbm.exec_query(cmd)

    def update_couchbase(self):
        
        self.cb_indexes()

        for n, k in (('oxAuthConfDynamic', 'configuration_oxauth'), ('oxTrustConfApplication', 'configuration_oxtrust')):
            result = self.cbm.exec_query('SELECT {} FROM `gluu` USE KEYS "{}"'.format(n,k))
            result_json = result.json()
            js_conf = result_json['results'][0][n]

            self.apply_persist_changes(js_conf, n)

            n1ql = 'UPDATE `gluu` USE KEYS "{}" SET gluu.{}={}'.format(k, n, json.dumps(js_conf))
            print "Executing", n1ql
            result = self.cbm.exec_query(n1ql)

        for k in self.delete_from_configuration:
            n1ql = 'UPDATE `gluu` USE KEYS "configuration" UNSET {}'.format(k)
            print "Executing", n1ql
            result = self.cbm.exec_query(n1ql)

        #self.update_gluu_couchbase()


    def update_gluu_couchbase(self):        
        self.setupObj.couchbaseProperties()


    def db_connection_ldap(self):
        gluu_ldap_prop = get_properties(self.setupObj.ox_ldap_properties)
        
        ldap_host = gluu_ldap_prop['servers'].split(',')[0].strip().split(':')[0]
        ldap_bind_dn = gluu_ldap_prop['bindDN']
        ldap_bind_pw = unobscure(gluu_ldap_prop['bindPassword'])

        for i in range(5):
            try:
                self.conn = ldap.initialize('ldaps://{0}:1636'.format(ldap_host))
                self.conn.simple_bind_s(ldap_bind_dn, ldap_bind_pw)
                return
            except:
                print "Can't connect to LDAP Server. Retrying in 5 secs ..."
                time.sleep(5)
                
        sys.exit("Max retry reached. Exiting...")

    def apply_persist_changes(self, js_conf, config_element):
        for key, change_type, how_change, value in self.persist_changes[config_element]:

            if change_type == 'add':
                if how_change == 'entry':
                    js_conf[key] = value
                elif how_change == 'element':
                    if not value in js_conf[key]:
                        js_conf[key].append(value)
            elif change_type == 'change':
                if how_change == 'entry':
                    js_conf[key] = value
                if how_change == 'subentry':
                    js_conf[key][value[0]] = value[1]
            elif change_type == 'remove':
                if how_change == 'entry':
                    if key in js_conf:
                        del js_conf[key]
                elif how_change == 'element':
                    if value in js_conf[key]:
                        js_conf[key].remove(value)


    def update_ldap(self):

        dn = 'ou=configuration,o=gluu'

        for config_element in self.persist_changes:
            print "Updating", config_element
            ldap_filter = '({0}=*)'.format(config_element)

            result = self.conn.search_s(dn, ldap.SCOPE_SUBTREE, ldap_filter, [config_element])

            sdn = result[0][0]
            js_conf = json.loads(result[0][1][config_element][0])
            self.apply_persist_changes(js_conf, config_element)
            new_conf = json.dumps(js_conf,indent=4)

            self.conn.modify_s(sdn, [( ldap.MOD_REPLACE, config_element,  new_conf)])

        result = self.conn.search_s(dn, ldap.SCOPE_BASE,  attrlist=self.delete_from_configuration)
        remove_list = []

        for k in result[0][1]:
            if result[0][1][k]:
                remove_list.append(( ldap.MOD_DELETE, k, result[0][1][k]))

        for entry in remove_list:
            self.conn.modify_s(dn, [entry])
    
        self.conn.unbind()
    
        # update opendj schema and restart
        self.setupObj.run(['cp', '-f', 
                            os.path.join(self.ces_dir, 'static/opendj/101-ox.ldif'),
                            self.setupObj.openDjSchemaFolder
                            ])
        print "Restarting OpenDJ ..."
        self.setupObj.run_service_command('opendj', 'stop')
        self.setupObj.run_service_command('opendj', 'start')

        self.db_connection_ldap()


    def download_apps(self):

        downloads = [
                    ('https://ox.gluu.org/maven/org/gluu/oxtrust-server/{0}{1}/oxtrust-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'identity.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxauth.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxauth-rp/{0}{1}/oxauth-rp-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxauth-rp.war')),
                    ('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/{0}/jetty-distribution-{0}.tar.gz'.format(self.setupObj.jetty_version), os.path.join(self.app_dir, 'jetty-distribution-{0}.tar.gz'.format(self.setupObj.jetty_version))),
                    ('https://repo1.maven.org/maven2/org/python/jython-installer/2.7.2/jython-installer-2.7.2.jar', os.path.join(self.app_dir, 'jython-installer-2.7.2.jar')),
                    ]

        if os.path.exists('/opt/shibboleth-idp'):
            downloads += [
                    ('https://ox.gluu.org/maven/org/gluu/oxshibbolethIdp/{0}{1}/oxshibbolethIdp-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'idp.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxShibbolethStatic/{0}{1}/oxShibbolethStatic-{0}{1}.jar'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'shibboleth-idp.jar')),
                    ('https://ox.gluu.org/maven/org/gluu/oxShibbolethKeyGenerator/{0}{1}/oxShibbolethKeyGenerator-{0}{1}.jar'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'idp3_cml_keygenerator.jar')),
                    ]

        if os.path.exists('/opt/gluu/node/passport'):
            downloads += [
                    ('https://ox.gluu.org/npm/passport/passport-{}.tgz'.format(self.up_version), os.path.join(self.app_dir, 'passport.tgz')),
                    ('https://ox.gluu.org/npm/passport/passport-version_{}-node_modules.tar.gz'.format(self.up_version), os.path.join(self.app_dir, 'passport-node_modules.tar.gz')),
                    ]

        if os.path.exists('/opt/gluu/radius'):
            downloads += [
                    ('https://ox.gluu.org/maven/org/gluu/super-gluu-radius-server/{0}{1}/super-gluu-radius-server-{0}{1}-distribution.zip'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'gluu-radius-libs.zip')),
                    ('https://ox.gluu.org/maven/org/gluu/super-gluu-radius-server/{0}{1}/super-gluu-radius-server-{0}{1}.jar'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'super-gluu-radius-server.jar')),
                    ]

        if os.path.exists('/opt/oxd-server'):
            downloads += [
                    ('https://ox.gluu.org/maven/org/gluu/oxd-server/{0}{1}/oxd-server-{0}{1}.jar'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxd-server.jar')),
                    ]

        if os.path.exists('/opt/gluu/jetty/casa'):
            downloads += [
                    ('https://ox.gluu.org/maven/org/gluu/casa/{0}{1}/casa-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'casa.war')),
                    ('https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_{0}/static/casa/scripts/casa-external_smpp.py'.format(self.up_version), '/opt/gluu/python/libs/casa-external_smpp.py'),
                    ]
            for p in self.casa_plugins:
                downloads.append((self.casa_plugins[p].format(self.up_version, self.build_tag), os.path.join(self.app_dir, p + '.jar')))

            downloads += [
                    ('https://github.com/GluuFederation/casa/raw/version_{}/plugins/account-linking/extras/casa.xhtml'.format(self.up_version), os.path.join(self.app_dir, 'casa.xhtml')),
                    ('https://raw.githubusercontent.com/GluuFederation/casa/version_4.1.0/plugins/account-linking/extras/casa.py', os.path.join(self.app_dir, 'casa.py')),
                    ]

        for download_link, out_file in downloads:
            print "Downloading", download_link
            self.setupObj.run(['wget', '-nv', download_link, '-O', out_file])

    def update_war_files(self):
        for service in self.setupObj.jetty_app_configuration:
            service_webapps_dir = os.path.join(self.setupObj.jetty_base, service, 'webapps')
            if os.path.exists(service_webapps_dir):
                self.setupObj.run(['cp', '-f', os.path.join(self.app_dir, service+'.war'), service_webapps_dir])

    def update_jetty(self):
        distAppFolder = self.setupObj.distAppFolder
        self.setupObj.distAppFolder = self.app_dir
        jetty_folder = os.readlink(self.setupObj.jetty_home)
        self.setupObj.run(['unlink', self.setupObj.jetty_home])
        self.setupObj.run(['rm', '-r', '-f', jetty_folder])
        self.setupObj.installJetty()
        self.setupObj.distAppFolder = distAppFolder

    def update_scripts(self):
        print "Updating Scripts"
        self.setupObj.prepare_base64_extension_scripts()
        self.setupObj.renderTemplate(self.setupObj.ldif_scripts)
        ldif_scripts_fn = os.path.join(self.setupObj.outputFolder, os.path.basename(self.setupObj.ldif_scripts))
        self.parser = self.setup.myLdifParser(ldif_scripts_fn)
        self.parser.parse()
        
        getattr(self, 'update_scripts_' + self.default_storage)()

    def update_scripts_couchbase(self):
        for dn, entry in self.parser.entries:
            if entry['inum'][0] in self.scripts_inum:
                scr_key = 'scripts_{}'.format(entry['inum'][0])
                print "Updating script:", scr_key
                result = self.cbm.exec_query('UPDATE `gluu` USE KEYS "{}" SET oxScript={}'.format(scr_key, json.dumps(entry['oxScript'][0])))
                result_data = result.json()
                print "Result", result_data['status']
 
    def update_scripts_ldap(self):
        self.db_connection_ldap()
        for dn, entry in self.parser.entries:
            if entry['inum'][0] in self.scripts_inum:
                try:
                    self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxScript',  entry['oxScript'][0])])
                except Exception as e:
                    ldif = modlist.addModlist(entry)
                    self.conn.add_s(dn, ldif)

    def update_apache_conf(self):
        print "Updating Apache Configuration"

        self.setupObj.outputFolder = os.path.join(self.ces_dir, 'output')
        self.setupObj.templateFolder = os.path.join(self.ces_dir, 'templates')

        self.setupObj.apache2_conf = os.path.join(self.ces_dir, 'output', os.path.basename(self.setupObj.apache2_conf))
        self.setupObj.apache2_ssl_conf = os.path.join(self.ces_dir, 'output', os.path.basename(self.setupObj.apache2_ssl_conf))
        self.setupObj.apache2_24_conf = os.path.join(self.ces_dir, 'output', os.path.basename(self.setupObj.apache2_24_conf))
        self.setupObj.apache2_ssl_24_conf = os.path.join(self.ces_dir, 'output', os.path.basename(self.setupObj.apache2_ssl_24_conf))

        apache_templates = {
                             self.setupObj.apache2_conf: False,
                             self.setupObj.apache2_ssl_conf: False,
                             self.setupObj.apache2_24_conf: False,
                             self.setupObj.apache2_ssl_24_conf: False,
                            }

        self.setupObj.render_templates(apache_templates)
        self.setupObj.configure_httpd()

    def render_template(self, tmp_file):
        data_dict = self.setupObj.__dict__
        data_dict.update(self.setupObj.templateRenderingDict)
        
        temp = self.setupObj.readFile(tmp_file)
        temp = self.setupObj.fomatWithDict(temp,  data_dict)
        
        return temp

    def update_shib(self):

        saml_meta_data_fn = '/opt/shibboleth-idp/metadata/idp-metadata.xml'

        if not os.path.exists(saml_meta_data_fn):
            return

        print "Updadting shibboleth-idp"

        print "Backing up ..."
        self.setupObj.run(['cp', '-r', '/opt/shibboleth-idp', '/opt/shibboleth-idp.back'])
        print "Updating idp-metadata.xml"
        self.setupObj.templateRenderingDict['idp3SigningCertificateText'] = open('/etc/certs/idp-signing.crt').read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')
        self.setupObj.templateRenderingDict['idp3EncryptionCertificateText'] = open('/etc/certs/idp-encryption.crt').read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')

        self.setupObj.backupFile(saml_meta_data_fn)

        os.chdir('/opt')
        self.setupObj.run(['/opt/jre/bin/jar', 'xf', os.path.join(self.app_dir,'shibboleth-idp.jar')])
        self.setupObj.run(['rm', '-r', '/opt/META-INF'])
        
        idp_tmp_dir = '/tmp/{0}'.format(str(int(time.time()*1000)))
        self.setupObj.run(['mkdir','-p', idp_tmp_dir])
        
        os.chdir(idp_tmp_dir)

        self.setupObj.run(['/opt/jre/bin/jar', 'xf', os.path.join(self.app_dir, 'idp.war')])
        self.setupObj.run(['rm', '-f', '/opt/shibboleth-idp/webapp/WEB-INF/lib/*'])
        self.setupObj.run(['cp', '-r', os.path.join(idp_tmp_dir, 'WEB-INF/'), '/opt/shibboleth-idp/webapp'])

        #Recreate idp-metadata.xml with new format
        temp_fn = os.path.join(self.ces_dir, 'static/idp3/metadata/idp-metadata.xml')
        new_saml_meta_data = self.render_template(temp_fn)
        self.setupObj.writeFile(saml_meta_data_fn, new_saml_meta_data)

        for prop_fn in ('idp.properties', 'ldap.properties', 'services.properties','saml-nameid.properties'):
            print "Updating", prop_fn
            properties = self.render_template(os.path.join(self.ces_dir, 'static/idp3/conf', prop_fn))
            self.setupObj.writeFile(os.path.join('/opt/shibboleth-idp/conf', prop_fn), properties)

        self.setupObj.run(['cp', '-f', '{}/app/saml-nameid.properties.vm'.format(cur_dir), '/opt/gluu/jetty/identity/conf/shibboleth3/idp/'])
        self.setupObj.run(['chown', '-R', 'jetty:jetty', '/opt/shibboleth-idp'])
        self.setupObj.run(['rm', '-r', '-f', idp_tmp_dir])

        os.chdir(cur_dir)

    def update_radius(self):
        
        radius_dir = '/opt/gluu/radius'
        if not os.path.exists(radius_dir):
            return
        
        print "Updating Gluu Radius Server"
        
        self.setupObj.copyFile(os.path.join(self.ces_dir, 'static/radius/etc/init.d/gluu-radius'), '/etc/init.d')
        self.setupObj.run(['chmod', '+x', '/etc/init.d/gluu-radius'])

        radius_libs = os.path.join(self.app_dir, 'gluu-radius-libs.zip')
        radius_jar = os.path.join(self.app_dir, 'super-gluu-radius-server.jar')

        self.setupObj.run(['unzip', '-o', '-q', radius_libs, '-d', radius_dir ])
        self.setupObj.copyFile(radius_jar, radius_dir)

        self.setupObj.copyFile(os.path.join(self.ces_dir, 'static/radius/etc/default/gluu-radius'), self.setupObj.osDefault)


    def update_oxd(self):
        if not os.path.exists('/opt/oxd-server'):
            return

        print "Updating oxd Server"
        self.setupObj.copyFile(
                    os.path.join(self.app_dir, 'oxd-server.jar'),
                    '/opt/oxd-server/lib'
                    )


    def update_casa(self):
        casa_base_dir = os.path.join(self.setupObj.jetty_base, 'casa')
        
        if not os.path.exists(casa_base_dir):
            return
        
        print "Updating casa"
        
        casa_plugins_dir = os.path.join(casa_base_dir, 'plugins')
        self.setupObj.run_service_command('casa', 'stop')
        
        self.setupObj.run(['cp', '-f', os.path.join(self.app_dir, 'casa.war'),
                                    os.path.join(casa_base_dir, 'webapps')])

        account_linking = None
        
        # update plugins
        for plugin in glob.glob(os.path.join(casa_plugins_dir,'*.jar')):
            plugin_zip = zipfile.ZipFile(plugin, "r")
            menifest = plugin_zip.read('META-INF/MANIFEST.MF')
            for l in menifest.splitlines():
                ls = l.strip()
                if ls.startswith('Plugin-Id'):
                    n = ls.find(':')
                    pid = ls[n+1:].strip()
                    if pid in self.casa_plugins:
                        jar_fn = os.path.join(self.app_dir, pid + '.jar')
                        self.setupObj.run(['rm', '-f', plugin])
                        self.setupObj.run(['cp', '-f', jar_fn, casa_plugins_dir])
                    if pid == 'account-linking':
                        account_linking = True

        if account_linking:
            self.setupObj.copyFile(
                    os.path.join(self.app_dir, 'casa.xhtml'),
                    os.path.join(self.setupObj.jetty_base, 'oxauth/custom/pages')
                    )
            
            scr = self.setupObj.readFile(os.path.join(self.app_dir, 'casa.py'))

            if self.default_storage == 'couchbase':
                result = self.cbm.exec_query('UPDATE `gluu` USE KEYS "scripts_BABA-CACA" SET oxScript={}'.format(json.dumps(scr)))
            elif self.default_storage == 'ldap':
                self.conn.modify_s('inum=BABA-CACA,ou=scripts,o=gluu', [( ldap.MOD_REPLACE, 'oxScript',  scr)])
        
        pylib_dir = os.path.join(self.setupObj.gluuOptPythonFolder, 'libs')
        libdir_base_url = 'https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_{}/static/casa/scripts'.format(self.up_version)
        for casa_lib in glob.glob(os.path.join(pylib_dir, 'casa-external*.py')):
            self.setupObj.backupFile(casa_lib)
            print "Updating", casa_lib
            casa_lib_fn = os.path.basename(casa_lib)
            cmd = ['wget', '-q',
                   os.path.join(libdir_base_url, casa_lib_fn),
                   '-O', os.path.join(pylib_dir, casa_lib_fn)
                   ]

            self.setupObj.run(cmd)
        
    def update_passport(self):

        if not os.path.exists(self.setupObj.gluu_passport_base):
            return


        backup_folder = self.setupObj.gluu_passport_base + '_' + self.backup_time

        self.setupObj.run(['mv', self.setupObj.gluu_passport_base, backup_folder])

        print "Updating Passport"
        
        print "Stopping passport server"
        
        self.setupObj.run_service_command('passport', 'stop')

        self.setupObj.run(['mkdir', '-p', self.setupObj.gluu_passport_base])

        print "Extracting passport.tgz into " + self.setupObj.gluu_passport_base 
        self.setupObj.run(['tar', '--strip', '1', '-xzf', os.path.join(cur_dir, 'app', 'passport.tgz'),
                         '-C', '/opt/gluu/node/passport', '--no-xattrs', '--no-same-owner', '--no-same-permissions'])
    
        print "Extracting passport node modules"
        modules_dir = '/opt/gluu/node/passport/node_modules'

        if not os.path.exists(modules_dir):
            self.setupObj.run(['mkdir', '-p', modules_dir])

        self.setupObj.run(['tar', '--strip', '1', '-xzf', os.path.join(cur_dir, 'app', 'passport-node_modules.tar.gz'),
                         '-C', modules_dir, '--no-xattrs', '--no-same-owner', '--no-same-permissions'])

        log_dir = '/opt/gluu/node/passport/server/logs'

        if not os.path.exists(log_dir): 
            self.setupObj.run(['mkdir',log_dir])

        # copy mappings
        for m_path in glob.glob(os.path.join(backup_folder, 'server/mappings/*.js')):
            with open(m_path) as f:
                fc = f.read()
                if re.search('profile["[\s\S]*"]', fc):
                    mfn = os.path.basename(m_path)
                    if not os.path.exists(os.path.join(self.setupObj.gluu_passport_base, 'server/mappings', mfn)):
                        self.setupObj.copyFile(m_path, os.path.join(self.setupObj.gluu_passport_base, 'server/mappings'))

        self.setupObj.run(['chown', '-R', 'node:node', '/opt/gluu/node/passport/'])


    def add_oxAuthUserId_pairwiseIdentifier(self):

        print "Adding oxAuthUserId to pairwiseIdentifier."
        print "This may take several minutes depending on your user number"

        if self.user_location == 'ldap':

            result = self.conn.search_s(
                            'ou=people,o=gluu',
                            ldap.SCOPE_SUBTREE, 
                            '(objectClass=pairwiseIdentifier)', 
                            ['*']
                            )

            for e in result:
                if not 'oxAuthUserId' in e[1]:
                    for dne in ldap.dn.str2dn(e[0]):
                        if dne[0][0] == 'inum':
                            oxAuthUserId =  dne[0][1]
                            self.conn.modify_s(e[0], [(ldap.MOD_ADD, 'oxAuthUserId', oxAuthUserId)])

        else:
            result = self.cbm.exec_query('SELECT META().id AS docid, * from `gluu_user` WHERE `objectClass`="pairwiseIdentifier"')
            if result.ok:
                data = result.json()
                if data.get('results'):
                    print "Populating oxAuthUserId for pairwiseIdentifier entries. Number of entries: {}".format(len(data['results']))
                    for user_entry in data['results']:
                        doc = user_entry.get('gluu_user')
                        if doc and not 'oxAuthUserId' in doc:
                            dn = doc['dn']
                            for dnr in ldap.dn.str2dn(dn):
                                if dnr[0][0] == 'inum':
                                    n1ql = 'UPDATE `gluu_user` USE KEYS "{}" SET `oxAuthUserId`="{}"'.format(user_entry['docid'], dnr[0][1])
                                    self.cbm.exec_query(n1ql)
                                    break

    def add_personInum_fido2(self):

        if self.user_location == 'ldap':
            result = self.conn.search_s('ou=people,o=gluu', ldap.SCOPE_SUBTREE, '(objectclass=oxDeviceRegistration)', ['*'])
            if result:
                print "Populating personInum for fido2 entries. Number of entries: {}".format(len(result))
                for entry in result:
                    dn = entry[0]
                    if not 'personInum' in entry[1]:
                        for dnr in ldap.dn.str2dn(dn):
                            if dnr[0][0] == 'inum':
                                inum = dnr[0][1]
                                self.conn.modify_s(dn, [(ldap.MOD_ADD, 'personInum', [bytes(inum)])])
                                break

        else:
            result = self.cbm.exec_query('SELECT META().id AS docid, * from `gluu_user` WHERE `objectClass`="oxDeviceRegistration"')
            if result.ok:
                data = result.json()
                if data.get('results'):
                    print "Populating personInum for fido2 entries. Number of entries: {}".format(len(data['results']))
                    for user_entry in data['results']:
                        doc = user_entry.get('gluu_user')
                        if doc and not 'personInum' in doc:
                            dn = doc['dn']
                            for dnr in ldap.dn.str2dn(dn):
                                if dnr[0][0] == 'inum':
                                    print(user_entry['docid'])
                                    n1ql = 'UPDATE `gluu_user` USE KEYS "{}" SET `personInum`="{}"'.format(user_entry['docid'], dnr[0][1])
                                    self.cbm.exec_query(n1ql)
                                    break


    def update_jython(self):

        #check if jython is up to date
        if os.path.isdir('/opt/jython-2.7.2'):
            return

        print "Upgrading Jython"

        for jython in glob.glob(os.path.join(self.setupObj.distAppFolder,'jython-installer-*')):
            if os.path.isfile(jython):
                print "Deleting", jython
                self.setupObj.run(['rm', '-r', jython])

        self.setupObj.run(['cp', '-f', os.path.join(self.app_dir, 'jython-installer-2.7.2.jar'), self.setupObj.distAppFolder])
 
        for cur_version in glob.glob('/opt/jython-2*'):
            if os.path.isdir(cur_version):
                print "Deleting", cur_version
                self.setupObj.run(['rm', '-r', cur_version])

        if os.path.islink('/opt/jython'):
            self.setupObj.run(['unlink', '/opt/jython'])
        
        self.setupObj.jython_version = '2.7.2'
        
        print "Installing Jython"
        self.setupObj.installJython()

updaterObj = GluuUpdater()
updaterObj.download_ces()
updaterObj.download_apps()
updaterObj.update_jython()
updaterObj.determine_persistence_type()
updaterObj.update_persistence_data()
updaterObj.update_scripts()
updaterObj.update_jetty()
updaterObj.update_war_files()
updaterObj.update_scripts()
updaterObj.update_apache_conf()
updaterObj.update_shib()
updaterObj.update_passport()
updaterObj.update_radius()
updaterObj.update_oxd()
updaterObj.update_casa()
updaterObj.add_oxAuthUserId_pairwiseIdentifier()
updaterObj.add_personInum_fido2()

print "Please logout from container and restart Gluu Server"
