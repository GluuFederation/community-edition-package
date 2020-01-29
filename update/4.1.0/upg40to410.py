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

if not os.path.exists('/etc/gluu/conf'):
    sys.exit('Please run this script inside Gluu container.')

from pyDes import *

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

"""
result = raw_input("Starting upgrade. CONTINUE? (y|N): ")
if not result.strip() or (result.strip() and result.strip().lower()[0] != 'y'):
    print "You can re-run this script to upgrade. Bye now ..."
    sys.exit()
"""

"""
1. IDP upgrade, hence we have to put new IDP with conf files
2. LDAP schema update
3. Add new CB indexes
4. Fixes to some scritps.
5. Update httpd conf
6. Update oxauth-config.json and oxtrust-config.json
"""

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

        from ces_current import setup
        from ces_current.pylib.cbm import CBM
        
        self.cbm_obj = CBM
        self.setup = setup
        self.setupObj = self.setup.Setup(self.ces_dir)
        self.setupObj.log = os.path.join(self.ces_dir, 'update.log')
        self.setupObj.logError = os.path.join(self.ces_dir, 'update_error.log')
        self.setup.attribDataTypes.startup(self.ces_dir)

    def determine_persistence_type(self):        
        gluu_prop = get_properties(self.setupObj.gluu_properties_fn)
        self.persistence_type = gluu_prop['persistence.type']
        getattr(self, 'db_connection_'+self.persistence_type)()

    def update_persistence_data(self):
        getattr(self, 'update_'+self.persistence_type)()

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
        cb_passwd = unobscure(gluu_cb_prop['auth.userPassword'])

        self.cbm = self.cbm_obj(cb_serevr, cb_admin, cb_passwd)

        self.cb_buckets = [ b.strip() for b in gluu_cb_prop['buckets'].split(',') ]
        
        self.cb_indexes()
        
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

        for bucket in self.cb_buckets:
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

        for n, k in (('oxAuthConfDynamic', 'configuration_oxauth'), ('oxTrustConfApplication', 'configuration_oxtrust')):
            result = self.cbm.exec_query('SELECT {} FROM `gluu` USE KEYS "{}"'.format(n,k))
            result_json = result.json()
            js_conf = result_json['results'][0][n]

            self.apply_persist_changes(js_conf, n)

            result = self.cbm.exec_query('update `gluu` USE KEYS "{}" set gluu.{}={}'.format(k, n, json.dumps(js_conf)))

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

        for download_link, out_file in (
                    ('https://ox.gluu.org/maven/org/gluu/oxshibbolethIdp/{0}{1}/oxshibbolethIdp-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'idp.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxtrust-server/{0}{1}/oxtrust-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'identity.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxauth.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxauth-rp/{0}{1}/oxauth-rp-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxauth-rp.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxShibbolethStatic/{0}{1}/oxShibbolethStatic-{0}{1}.jar'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'shibboleth-idp.jar')),
                    ('https://ox.gluu.org/maven/org/gluu/oxShibbolethKeyGenerator/{0}{1}/oxShibbolethKeyGenerator-{0}{1}.jar'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'idp3_cml_keygenerator.jar')),
                    ('https://ox.gluu.org/npm/passport/passport-{}.tgz'.format(self.up_version), os.path.join(self.app_dir, 'passport.tgz')),
                    ('https://ox.gluu.org/npm/passport/passport-version_{}-node_modules.tar.gz'.format(self.up_version), os.path.join(self.app_dir, 'passport-node_modules.tar.gz')),
                    ('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/{0}/jetty-distribution-{0}.tar.gz'.format(self.setupObj.jetty_version), os.path.join(self.app_dir, 'jetty-distribution-{0}.tar.gz'.format(self.setupObj.jetty_version))),
                ):

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
        self.setupObj.prepare_base64_extension_scripts()
        self.setupObj.renderTemplate(self.setupObj.ldif_scripts)
        self.ldif_scripts_fn = os.path.join(self.setupObj.outputFolder, os.path.basename(self.setupObj.ldif_scripts))
        getattr(self, 'update_scripts_'+self.persistence_type)()

    def update_scripts_couchbase(self):
        documents = self.setup.get_documents_from_ldif(self.ldif_scripts_fn)
        scr_keys = [ 'scripts_{}'.format(inum) for inum in self.scripts_inum ]

        for k, doc in documents:
            if k in scr_keys:                
                query = 'UPSERT INTO `gluu` (KEY, VALUE) VALUES ("%s", %s)' % (k, json.dumps(doc))
                result = self.cbm.exec_query(query)
                print result.json()

    def update_scripts_ldap(self):
        parser = self.setup.myLdifParser(self.ldif_scripts_fn)
        parser.parse()
        
        for dn, entry in parser.entries:
            if entry['inum'][0] in self.scripts_inum:
                try:
                    self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxScript',  entry['oxScript'][0])])
                except Exception as e:
                    ldif = modlist.addModlist(entry)
                    self.conn.add_s(dn, ldif)

updaterObj = GluuUpdater()

updaterObj.download_ces()

from ces_current.pylib import Properties

updaterObj.determine_persistence_type()
updaterObj.update_persistence_data()
updaterObj.download_apps()
updaterObj.update_jetty()
updaterObj.update_war_files()
updaterObj.update_scripts()
