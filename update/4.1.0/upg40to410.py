#!/usr/bin/python

import os
import sys
import time
import json
import ldap
import pyDes
import base64
import ldap.modlist as modlist

cur_dir = os.path.dirname(os.path.realpath(__file__))

# TODO: 
# 1. casa upgrade

if not os.path.exists('/etc/gluu/conf'):
    sys.exit('Please run this script inside Gluu container.')

from pyDes import *

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)


setup_properties_fn = '/install/community-edition-setup/setup.properties.last'

if not os.path.exists(setup_properties_fn):
    print "Setup Properties File {} not found".format(setup_properties_fn)
    print "Can't continue. Exiting ..."
    sys.exit()

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
        self.up_version = '4.1.0'
        self.build_tag = '.Final'
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

        self.scripts_inum = ['2DAF-BA90', '2FDB-CF02', 'D40C-1CA4', '09A0-93D7', '92F0-BF9E', '09A0-93D6', '2124-0CF1', '2DAF-BA91']

        if not os.path.exists(self.app_dir):
            os.mkdir(self.app_dir)

        

    def download_ces(self):
        
        if not os.path.exists(self.ces_dir):
            ces_url = 'https://github.com/GluuFederation/community-edition-setup/archive/version_{}.zip'.format(self.up_version)
            print "Downloading Community Edition Setup {}".format(self.up_version)
            os.system('wget -q {} -O version_{}.zip'.format(ces_url, self.up_version))
            print "Extracting CES package"
            os.system('unzip -o -qq version_{}.zip'.format(self.up_version))
            os.system('mv community-edition-setup-version_{} ces_current'.format(self.up_version))
            os.system('rm version_{}.zip'.format(self.up_version))

        open(os.path.join(self.ces_dir, '__init__.py'),'w').close()
        sys.path.append('ces_current')

        global Properties
        from ces_current import setup
        from ces_current.pylib.cbm import CBM
        from ces_current.pylib import Properties
        
        self.cbm_obj = CBM
        self.setup = setup
        self.setupObj = self.setup.Setup(self.ces_dir)
        self.setupObj.log = os.path.join(self.ces_dir, 'update.log')
        self.setupObj.logError = os.path.join(self.ces_dir, 'update_error.log')
        self.setup.attribDataTypes.startup(self.ces_dir)
        self.setupObj.os_type, self.setupObj.os_version = self.setupObj.detect_os_type()
        self.setupObj.os_initdaemon = self.setupObj.detect_initd()

        self.setup_prop = get_properties(setup_properties_fn)

    def determine_persistence_type(self):        
        self.cb_buckets = []
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
        elif self.persistence_type == 'hybrid':
            self.db_connection_ldap()
            self.db_connection_couchbase()

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
        self.setupObj.mappingLocations = json.loads(self.setup_prop['mappingLocations'])
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

            result = self.cbm.exec_query('update `gluu` USE KEYS "{}" set gluu.{}={}'.format(k, n, json.dumps(js_conf)))

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

        for config_element in self.persist_changes:
            print "Updating", config_element
            ldap_filter = '({0}=*)'.format(config_element)
            result = self.conn.search_s('ou=configuration,o=gluu',ldap.SCOPE_SUBTREE, ldap_filter, [config_element])

            dn = result[0][0]

            js_conf = json.loads(result[0][1][config_element][0])

            self.apply_persist_changes(js_conf, config_element)

            new_conf = json.dumps(js_conf,indent=4)
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, config_element,  new_conf)])

        
        # update opendj schema and restart
        self.setupObj.run(['cp', '-f', 
                            os.path.join(self.ces_dir, 'static/opendj/101-ox.ldif'),
                            self.setupObj.openDjSchemaFolder
                            ])
        self.setupObj.run_service_command('opendj', 'stop')
        self.setupObj.run_service_command('opendj', 'start')


    def download_apps(self):

        downloads = [
                    ('https://ox.gluu.org/maven/org/gluu/oxtrust-server/{0}{1}/oxtrust-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'identity.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxauth.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxauth-rp/{0}{1}/oxauth-rp-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxauth-rp.war')),
                    ('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/{0}/jetty-distribution-{0}.tar.gz'.format(self.setupObj.jetty_version), os.path.join(self.app_dir, 'jetty-distribution-{0}.tar.gz'.format(self.setupObj.jetty_version))),
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
        self.ldif_scripts_fn = os.path.join(self.setupObj.outputFolder, os.path.basename(self.setupObj.ldif_scripts))
        getattr(self, 'update_scripts_' + self.default_storage)()

    def update_scripts_couchbase(self):
        
        documents = self.setup.get_documents_from_ldif(self.ldif_scripts_fn)
        scr_keys = [ 'scripts_{}'.format(inum) for inum in self.scripts_inum ]

        for k, doc in documents:
            if k in scr_keys:                
                query = 'UPSERT INTO `gluu` (KEY, VALUE) VALUES ("%s", %s)' % (k, json.dumps(doc))
                print "Updating script:", k
                result = self.cbm.exec_query(query)
                result_data = result.json()
                print "Result", result_data['status']

    def update_scripts_ldap(self):
        
        self.db_connection_ldap()
        
        parser = self.setup.myLdifParser(self.ldif_scripts_fn)
        parser.parse()
        
        for dn, entry in parser.entries:
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
        print "Updating Gluu Radius Server"

        radius_dir = '/opt/gluu/radius'
        if not os.path.exists(radius_dir):
            return
        
        self.setupObj.copyFile(os.path.join(self.ces_dir, 'static/radius/etc/init.d/gluu-radius'), '/etc/init.d')
        self.setupObj.run(['chmod', '+x', '/etc/init.d/gluu-radius'])

        radius_libs = os.path.join(self.app_dir, 'gluu-radius-libs.zip')
        radius_jar = os.path.join(self.app_dir, 'super-gluu-radius-server.jar')

        self.setupObj.run(['unzip', '-o', '-q', radius_libs, '-d', radius_dir ])
        self.setupObj.copyFile(radius_jar, radius_dir)

        self.setupObj.copyFile(os.path.join(self.ces_dir, 'static/radius/etc/default/gluu-radius'), self.setupObj.osDefault)
            
    def update_oxd(self):
        print "Updating oxd Server"
        self.setupObj.copyFile(
                    os.path.join(self.app_dir, 'oxd-server.jar'),
                    '/opt/oxd-server/lib'
                    )
        

updaterObj = GluuUpdater()

updaterObj.download_ces()

updaterObj.determine_persistence_type()
updaterObj.update_persistence_data()
updaterObj.download_apps()
updaterObj.update_jetty()
updaterObj.update_war_files()
updaterObj.update_scripts()
updaterObj.setupObj.load_properties(setup_properties_fn)
updaterObj.update_apache_conf()
updaterObj.update_shib()
updaterObj.update_radius()
updaterObj.update_oxd()

print "Please logout from container and restart Gluu Server"
