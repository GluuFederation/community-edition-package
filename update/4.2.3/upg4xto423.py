#!/usr/bin/python3

import sys
import shutil
import os
import re
import time
import json
import base64
import glob
import zipfile
import csv
import uuid
import urllib.request

if sys.version_info.major < 3:
    print("This script runs under Python 3")
    sys.exit()

installer = shutil.which('yum') if shutil.which('yum') else shutil.which('apt')

if not os.path.exists('/etc/gluu/conf'):
    sys.exit('Please run this script inside Gluu container.')

if sys.version_info.major < 3:
    print("This script runs on python 3")
    sys.exit()


os_type, os_version = '', ''
with open("/etc/os-release") as f:
    reader = csv.reader(f, delimiter="=")
    for row in reader:
        if row:
            if row[0] == 'ID':
                os_type = row[1].lower()
                if os_type == 'rhel':
                    os_type = 'redhat'
            elif row[0] == 'VERSION_ID':
                os_version = row[1].split('.')[0]

missing_packages = []

try:
    import ldap3
except:
    missing_packages.append('python3-ldap3')

try:
    import requests
except:
    missing_packages.append('python3-requests')

try:
    import six
except:
    if installer.endswith('apt'):
        missing_packages.append('python3-six')
    elif installer.endswith('yum') and os_version == '7':
        missing_packages.append('python36-six')
    else:
        missing_packages.append('python3-six')

try:
    import ruamel.yaml
except:
    if installer.endswith('apt'):
        missing_packages.append('python3-ruamel.yaml')
    elif installer.endswith('yum') and os_version == '7':
        missing_packages.append('python36-ruamel-yaml')
    else:
        missing_packages.append('python3-ruamel-yaml')
    
packages = ' '.join(missing_packages)

if packages:
    print("This script requires", packages)
    cmd = installer +' install -y ' + packages
    prompt = input("Install with command {}? [Y/n] ".format(cmd))
    if not prompt.strip() or prompt[0].lower() == 'y':
        if installer.endswith('apt'):
            cmd_up = 'apt-get -y update'
            print("Executing", cmd_up)
            os.system(cmd_up)
        os.system(cmd)
    else:
        print("Can't continue without installing packages. Exiting ...")
        sys.exit()

import ldap3
import ruamel.yaml
from ldap3.utils import dn as dnutils

cur_dir = os.path.dirname(os.path.realpath(__file__))
properties_password = None

result = input("Starting upgrade. CONTINUE? (y|N): ")
if not result.strip() or (result.strip() and result.strip().lower()[0] != 'y'):
    print("You can re-run this script to upgrade. Bye now ...")
    sys.exit()

def get_properties(prop_fn):
    
    pp = Properties()
    
    with open(prop_fn, 'rb') as file_object:
        pp.load(file_object, 'utf-8')

    p = {}
    for k in pp:
        v = pp[k].data
        if v.lower() == 'true':
            v == True
        elif v.lower() == 'false':
            v == False

        p[k] = v

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
    return [ flatten('{}'.format(k)) for k in l ]

class GluuUpdater:
    def __init__(self):
        self.ces_dir = os.path.join(cur_dir, 'ces_current')
        self.up_version = '4.2.3'
        self.build_tag = '.Final'
        self.backup_time = time.strftime('%Y-%m-%d.%H:%M:%S')
        self.app_dir = os.path.join(cur_dir, 'app')
        self.postmessages = []
        self.opendjNeedsUpdate = False

        # app versions
        self.corretto_version = '11.0.8.10.1'
        self.jython_version = '2.7.2'
        self.jetty_version = '9.4.35.v20201120'

        self.delete_from_configuration = ['gluuFreeDiskSpace', 'gluuFreeMemory', 'gluuFreeSwap', 'gluuGroupCount', 'gluuIpAddress', 'gluuPersonCount', 'gluuSystemUptime']

        self.casa_plugins = {
            'strong-authn-settings': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/strong-authn-settings/{0}{1}/strong-authn-settings-{0}{1}-jar-with-dependencies.jar',
            'account-linking': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/account-linking/{0}{1}/account-linking-{0}{1}-jar-with-dependencies.jar',
            'authorized-clients': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/authorized-clients/{0}{1}/authorized-clients-{0}{1}-jar-with-dependencies.jar',
            'custom-branding': 'https://ox.gluu.org/maven/org/gluu/casa/plugins/custom-branding/{0}{1}/custom-branding-{0}{1}-jar-with-dependencies.jar',
            }

        if not os.path.exists(self.app_dir):
            os.mkdir(self.app_dir)

    def stop_services(self):
        print("Stopping Gluu Services")
        for service in ('oxauth', 'identity', 'idp', 'oxauth-rp',  'oxd-server', 'casa', 'scim', 'fido2', 'passport'):
            os.system('systemctl stop ' + service)

        print("Cleaning Jetty cache")
        os.system('rm -r -f /opt/jetty-9.4/temp/*')


    def download_ces(self):
        
        if not os.path.exists(self.ces_dir):
            ces_url = 'https://github.com/GluuFederation/community-edition-setup/archive/version_{}.zip'.format(self.up_version)

            print("Downloading Community Edition Setup {}".format(self.up_version))
            target_fn = os.path.join(cur_dir, 'version_{}.zip'.format(self.up_version))

            os.system('wget -q {} -O {}'.format(ces_url, target_fn))
            
            #determine path
            ces_zip = zipfile.ZipFile(target_fn, "r")
            ces_zip_path = ces_zip.namelist()[0]

            print("Extracting CES package")
            os.system('unzip -o -qq {}'.format(target_fn))
            extracted_path = os.path.join(cur_dir, ces_zip_path)
            os.system('mv {} {}'.format(extracted_path, self.ces_dir))
            os.system('wget -nv https://raw.githubusercontent.com/GluuFederation/community-edition-setup/master/pylib/generate_properties.py -O {}'.format(os.path.join(self.ces_dir, 'pylib', 'generate_properties.py')))
            os.system('rm ' + target_fn)

        open(os.path.join(self.ces_dir, '__init__.py'),'w').close()
        sys.path.append('ces_current')

        global Properties
        global pyDes
        global ObjectClass

        from ces_current import setup
        from ces_current.pylib.cbm import CBM
        from ces_current.pylib import pyDes
        from ces_current.pylib.jproperties import Properties
        from ces_current.pylib.generate_properties import generate_properties
        from ces_current.pylib.gluu_utils import myLdifParser, get_documents_from_ldif, get_key_from
        from ces_current.pylib.schema import ObjectClass

        self.get_documents_from_ldif = get_documents_from_ldif
        self.get_key_from = get_key_from
        self.cbm_obj = CBM
        self.setup = setup
        self.setupObj = self.setup.Setup(self.ces_dir)
        self.setupObj.log = os.path.join(self.ces_dir, 'update.log')
        self.setupObj.logError = os.path.join(self.ces_dir, 'update_error.log')
        self.setupObj.os_type, self.setupObj.os_version = self.setupObj.detect_os_type()
        self.setupObj.os_initdaemon = self.setupObj.detect_initd()
        self.setupObj.apache_version = self.setupObj.determineApacheVersionForOS()

        self.setupObj.properties_password = properties_password
        self.setupObj.jetty_version = self.jetty_version
        self.setupObj.jre_version = self.corretto_version
        self.myLdifParser = myLdifParser

        print("Collecting properties")
        self.setup_prop = generate_properties(True)
        
        if not 'oxtrust_admin_password' in self.setup_prop:
            self.setup_prop['oxtrust_admin_password'] = self.setup_prop['ldapPass']

        for setup_key in self.setup_prop:
            setattr(self.setupObj, setup_key, self.setup_prop[setup_key])

        self.setupObj.ldapCertFn = self.setupObj.opendj_cert_fn
        self.setupObj.ldapTrustStoreFn = self.setupObj.opendj_p12_fn
        self.setupObj.calculate_selected_aplications_memory()
        self.setupObj.encode_passwords()

        self.casa_base_dir = os.path.join(self.setupObj.jetty_base, 'casa')

        self.setupObj.set_systemd_timeout()


    def prepare_persist_changes(self):
        self.persist_changes = { 
                    ('oxAuthConfDynamic', 'ou=oxauth,ou=configuration,o=gluu'): [
                        ('tokenEndpointAuthMethodsSupported', 'add', 'element', "tls_client_auth"),
                        ('tokenEndpointAuthMethodsSupported', 'add', 'element', "self_signed_tls_client_auth"),
                        ('spontaneousScopeLifetime', 'add', 'entry', 86400),
                        ('cleanServiceInterval', 'change', 'entry',  60),
                        ('cleanServiceBatchChunkSize', 'change', 'entry',  10000),
                        ('metricReporterEnabled', 'remove', 'entry', None),
                        ('useLocalCache', 'add', 'entry', True),
                        ('backchannelAuthenticationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/bc-authorize'.format(self.setup_prop['hostname'])),
                        ('backchannelDeviceRegistrationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/bc-deviceRegistration'.format(self.setup_prop['hostname'])),
                        ('uiLocalesSupported', 'change', 'entry', ['en', 'bg', 'de', 'es', 'fr', 'it', 'ru', 'tr']),
                        ('clientRegDefaultToCodeFlowWithRefresh', 'add', 'entry', True),
                        ('changeSessionIdOnAuthentication', 'add', 'entry', True),
                        ('returnClientSecretOnRead', 'add', 'entry', True),
                        ('fido2Configuration', 'remove', 'entry', None),
                        ('loggingLevel', 'add', 'entry', 'INFO'),
                        ('loggingLayout', 'add', 'entry', 'text'),
                        ('errorHandlingMethod', 'add', 'entry', 'internal'),
                        ('useLocalCache', 'add', 'entry', True),
                        ('backchannelTokenDeliveryModesSupported', 'add', 'entry', []),
                        ('backchannelAuthenticationRequestSigningAlgValuesSupported', 'add', 'entry', []),
                        ('backchannelClientId', 'add', 'entry', ''),
                        ('backchannelRedirectUri', 'add', 'entry', ''),
                        ('backchannelUserCodeParameterSupported', 'add', 'entry', False),
                        ('backchannelBindingMessagePattern', 'add', 'entry', '^[a-zA-Z0-9]{4,8}$'),
                        ('backchannelAuthenticationResponseExpiresIn', 'add', 'entry',  3600),
                        ('backchannelAuthenticationResponseInterval', 'add', 'entry', 2),
                        ('backchannelRequestsProcessorJobIntervalSec', 'add', 'entry', 0),
                        ('backchannelRequestsProcessorJobChunkSize', 'add', 'entry', 100),
                        ('cibaGrantLifeExtraTimeSec', 'add', 'entry', 180),
                        ('cibaMaxExpirationTimeAllowedSec', 'add', 'entry',  1800),
                        ('backchannelLoginHintClaims', 'add', 'entry', ['inum', 'uid', 'mail']),
                        ('cibaEndUserNotificationConfig', 'add', 'entry', {'databaseURL': '', 'notificationKey': '', 'appId': '', 'storageBucket': '', 'notificationUrl': '', 'messagingSenderId': '', 'publicVapidKey': '', 'projectId': '', 'authDomain': '', 'apiKey': ''}),
                        ('deviceAuthorizationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/device-authorization'.format(self.setup_prop['hostname'])),
                        ('grantTypesSupported', 'add', 'element', 'urn:ietf:params:oauth:grant-type:device_code'),
                        ('dynamicGrantTypeDefault', 'add', 'element', 'urn:ietf:params:oauth:grant-type:device_code'),
                        ('deviceAuthzRequestExpiresIn', 'add', 'entry', 1800),
                        ('deviceAuthzTokenPollInterval', 'add', 'entry', 5),
                        ('deviceAuthzResponseTypeToProcessAuthz', 'add', 'entry', 'code'),
                    ],
    
                    ('oxAuthConfStatic', 'ou=oxauth,ou=configuration,o=gluu'): [
                        ('baseDn', 'change', 'subentry', ('sessions', 'ou=sessions,o=gluu')),
                        ('baseDn', 'change', 'subentry', ('ciba', 'ou=ciba,o=gluu')),
                    ],
    
                    ('oxTrustConfApplication', 'ou=oxtrust,ou=configuration,o=gluu'): [
                        ('useLocalCache', 'add', 'entry', True),
                        ('loggingLayout', 'add', 'entry', 'text'),
                    ],
                    
                    ('oxConfApplication', 'ou=oxidp,ou=configuration,o=gluu'): [
                            ('scriptDn', 'add', 'entry', 'ou=scripts,o=gluu'),
                    ],
                    
                    ('oxTrustConfCacheRefresh', 'ou=oxtrust,ou=configuration,o=gluu'): [
                        ('inumConfig', 'change', 'subentry', ('bindDN', self.setupObj.ldap_binddn)),
                    ]

                }


    def determine_persistence_type(self):
        self.cb_buckets = []
        self.user_location = 'ldap'
        self.sessions_location = 'ldap'
        gluu_prop = get_properties(self.setupObj.gluu_properties_fn)
        self.persistence_type = gluu_prop['persistence.type']
        self.default_storage = self.persistence_type

        if self.persistence_type == 'hybrid':
            hybrid_prop = get_properties(self.setupObj.gluu_hybrid_roperties, raw=True)
            self.default_storage = hybrid_prop['storage.default'].data

        if self.persistence_type == 'ldap':
            self.db_connection_ldap()
        elif self.persistence_type == 'couchbase':
            self.db_connection_couchbase()
            self.user_location = 'couchbase'
            self.sessions_location = 'couchbase'
        elif self.persistence_type == 'hybrid':
            self.db_connection_ldap()
            self.db_connection_couchbase()
            if 'people' in hybrid_prop['storage.couchbase.mapping'].data:
                self.user_location = 'couchbase'
            if 'token' in hybrid_prop['storage.couchbase.mapping'].data:
                self.sessions_location = 'couchbase'

            if ('token' in hybrid_prop['storage.couchbase.mapping'].data) and (not 'sessions' in hybrid_prop['storage.couchbase.mapping'].data):
                hybrid_prop['storage.couchbase.mapping'] = hybrid_prop['storage.couchbase.mapping'].data + ', sessions'
                self.setupObj.backupFile(self.setupObj.gluu_hybrid_roperties)
                with open(self.setupObj.gluu_hybrid_roperties, "wb") as w:
                    hybrid_prop.store(w, timestamp=False)

    def fix_gluu_config(self):
        print("Fixing Gluu configuration files")
        with open(self.setupObj.gluu_properties_fn) as f:
            gluu_prop = f.readlines()

        for l in gluu_prop:
            if l.startswith('fido2_ConfigurationEntryDN'):
                break
        else:
            for i, l in enumerate(gluu_prop[:]):
                if l.strip().startswith('oxradius_ConfigurationEntryDN'):
                    gluu_prop.insert(i+1, 'fido2_ConfigurationEntryDN=ou=fido2,ou=configuration,o=gluu\n')
                    break

            self.setupObj.writeFile(self.setupObj.gluu_properties_fn, ''.join(gluu_prop))


        idp_default_fn = '/etc/default/idp'

        if os.path.exists(idp_default_fn):
            with open(idp_default_fn) as f:
                idp_default = f.readlines()
            
            for i, l in enumerate(idp_default[:]):
                ls = l.strip()
                if ls.startswith('JAVA_OPTIONS') and not '-Dpython.home' in ls:
                    n = ls.find('=')
                    options = ls[n+1:].strip()
                    if options.startswith('"') and options.endswith('"'):
                        options = options.strip('"').strip()
                    elif options.startswith("'") and options.endswith("'"):
                        options = options.strip("'").strip()

                    options += ' -Dpython.home=' + self.setupObj.jython_home
                    idp_default[i] = 'JAVA_OPTIONS="{}"\n'.format(options)
                    self.setupObj.writeFile(idp_default_fn, ''.join(idp_default))

        passport_default_fn = '/etc/default/passport'
        if os.path.exists(passport_default_fn):
            passport_default = self.render_template(os.path.join(self.ces_dir, 'templates/node/passport'))
            self.setupObj.writeFile(passport_default_fn, passport_default)


        if os.path.exists(self.setupObj.gluuCouchebaseProperties):
            gluu_couchbase_prop_s = self.setupObj.readFile(self.setupObj.gluuCouchebaseProperties)
            gluu_couchbase_prop = gluu_couchbase_prop_s.splitlines()
            for i, l in enumerate(gluu_couchbase_prop[:]):
                if l.startswith('bucket.gluu_token.mapping'):
                    n = l.find(':')
                    mapping = l[n+1:].strip()
                    mapping_list = [m.strip() for m in mapping.split(',')]
                    if not 'sessions' in mapping_list:
                        mapping_list.append('sessions')
                        gluu_couchbase_prop[i] = 'bucket.gluu_token.mapping: {}'.format(', '.join(mapping_list))
                        self.setupObj.writeFile(self.setupObj.gluuCouchebaseProperties, '\n'.join(gluu_couchbase_prop))


    def update_persistence_data(self):
        getattr(self, 'update_' + self.default_storage)()

    def checkRemoteSchema(self):

        s_base = 'cn=Subschema' if self.ldap_type == 'openldap' else 'cn=schema'
        
        self.conn.search(
                        search_base=s_base, 
                        search_scope=ldap3.BASE, 
                        search_filter='(objectclass=*)',
                        attributes=['objectClasses']
                        )
        result = self.conn.response

        for obj_s in result[0]['attributes']['objectClasses']:
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
        self.setupObj.cbm = self.cbm

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
        print("Removing index", index_name)
        self.cbm.exec_query(cmd)

    def add_index(self, bucket, ind):
        cmd, index_name = self.setupObj.couchbaseMakeIndex(bucket, ind)
        if 'defer_build' in cmd:
            if not bucket in self.new_cb_indexes:
                self.new_cb_indexes[bucket] = []
            self.new_cb_indexes[bucket].append(index_name)
        print("Executing", cmd)
        self.cbm.exec_query(cmd)

    def cb_indexes(self):
        print("Updating Couchbase indexes")

        self.new_cb_indexes = {}
        new_index_json_fn = os.path.join(self.ces_dir, 'static/couchbase/index.json')
        new_index_json_s = self.setupObj.readFile(new_index_json_fn)
        new_index_json_s = new_index_json_s.replace('!bucket_prefix!', self.setupObj.couchbase_bucket_prefix)
        new_indexes = json.loads(new_index_json_s)

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
            print("Executing", cmd)
            self.cbm.exec_query(cmd)

    def get_existing_buckets(self):
        existing_buckets = []
        r = self.cbm.get_buckets()

        if r.ok:
            b_ = r.json()
            existing_buckets = [ bucket['name'] for bucket in b_ ]        

        return existing_buckets

    def update_couchbase(self):


        if self.setupObj.couchbase_bucket_prefix+'_token' in self.setupObj.couchbaseBuckets:
            session_bucket = self.setupObj.couchbase_bucket_prefix + '_session'
            self.setupObj.couchbaseBuckets.append(session_bucket)
            self.setupObj.mappingLocations['session'] = 'couchbase'
            
            #add missing buckets:
            existing_buckets = self.get_existing_buckets()
            
            if not session_bucket in  existing_buckets:
                bcr = self.cbm.add_bucket(session_bucket, self.setupObj.couchbaseBucketDict['session']['memory_allocation'])
                
                if not bcr.ok:
                    print("Failed to create bucket {}, reason: {}".format(session_bucket, bcr.text))
                    print("Please solve the issue. Exiting for now.")
                else:
                    print("Bucket {} created".format(session_bucket))
                    self.postmessages.append("Please use couchbase administrator panel and adjust Memory Quota for bucket {}".format(session_bucket))

            #check if bucket is ready for five times
            for i in range(5):
                time.sleep(2)
                existing_buckets = self.get_existing_buckets()
                if session_bucket in existing_buckets:
                    break

            # get all sessions from gluu_token, add sid if not exists and move to gluu_session
            result = self.cbm.exec_query('SELECT META().id FROM `{}_token` WHERE exp > "" and objectClass = "oxAuthSessionId"'.format(self.setupObj.couchbase_bucket_prefix))

            if result.ok:
                data = result.json()
                for d in data.get('results',[]):
                    docid = d['id']
                    #remove session entry:
                    self.cbm.exec_query('DELETE FROM `{}_token` USE KEYS "{}"'.format(self.setupObj.couchbase_bucket_prefix, docid))

                    #rsid = self.cbm.exec_query('SELECT * FROM `{}_token` USE KEYS "{}"'.format(self.setupObj.couchbase_bucket_prefix, docid))
                    #if rsid.ok:
                    #    dsid = rsid.json()
                    #    docc = dsid.get('results',[{}])[0]
                    #    if docc:
                    #        doc = docc[self.setupObj.couchbase_bucket_prefix+'_token']
                    #        if not 'sid' in doc:
                    #            doc['sid'] = str(uuid.uuid4())
                    #        if not 'session_id' in doc['oxAuthSessionAttribute']:
                    #            doc['oxAuthSessionAttribute']['session_id'] = str(uuid.uuid4())
                    #    print("Moving", docid, "to", self.setupObj.couchbase_bucket_prefix+'_session')
                    #    n1ql = 'UPSERT INTO `%s_session` (KEY, VALUE) VALUES ("%s", %s)' % (self.setupObj.couchbase_bucket_prefix, docid, json.dumps(doc))
                    #    radds = self.cbm.exec_query(n1ql)
                    #    print(radds.json())
                    #    if radds.ok and radds.json()['status'] == 'success':
                    #        rx = self.cbm.exec_query('DELETE FROM `{}_token` USE KEYS "{}"'.format(self.setupObj.couchbase_bucket_prefix, docid))

            self.setupObj.couchbaseProperties()

        self.cb_indexes()

        for n, dn in self.persist_changes:
            k = self.get_key_from(dn)
            result = self.cbm.exec_query('SELECT {} FROM `{}` USE KEYS "{}"'.format(n, self.setupObj.couchbase_bucket_prefix, k))
            result_json = result.json()
            js_conf = result_json['results'][0][n]

            self.apply_persist_changes(js_conf, self.persist_changes[(n, dn)])

            n1ql = 'UPDATE `{}` USE KEYS "{}" SET {}.{}={}'.format(self.setupObj.couchbase_bucket_prefix, k, self.setupObj.couchbase_bucket_prefix, n, json.dumps(js_conf))
            print("Executing", n1ql)
            result = self.cbm.exec_query(n1ql)

        for k in self.delete_from_configuration:
            n1ql = 'UPDATE `{}` USE KEYS "configuration" UNSET {}'.format(self.setupObj.couchbase_bucket_prefix, k)
            print("Executing", n1ql)
            result = self.cbm.exec_query(n1ql)


        #copy sessions from gluu_token to gluu_session and add sid

        #self.update_gluu_couchbase()


    def update_gluu_couchbase(self):        
        self.setupObj.couchbaseProperties()


    def db_connection_ldap(self):
        gluu_ldap_prop = get_properties(self.setupObj.ox_ldap_properties)
        
        ldap_server_string = gluu_ldap_prop['servers'].split(',')[0].strip()
        self.ldap_host, self.ldap_port = ldap_server_string.split(':')
        self.ldap_bind_dn = gluu_ldap_prop['bindDN']
        self.ldap_bind_pw = unobscure(gluu_ldap_prop['bindPassword'])

        self.setupObj.createLdapPw()

        for i in range(5):
            
            ldap_server = ldap3.Server(self.ldap_host, port=int(self.ldap_port), use_ssl=True)
            self.conn = ldap3.Connection(ldap_server, user=self.ldap_bind_dn, password=self.ldap_bind_pw)

            try:
                self.conn.bind()
                return
            except Exception as e:
                print(e)
                print("Can't connect to LDAP Server. Retrying in 5 secs ...")
                time.sleep(5)

        sys.exit("Max retry reached. Exiting...")

    def apply_persist_changes(self, js_conf, data):
        for key, change_type, how_change, value in data:
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

        for config_element, config_dn in self.persist_changes:
            print("Updating", config_element)
            ldap_filter = '({0}=*)'.format(config_element)

            self.conn.search(
                        search_base=config_dn, 
                        search_scope=ldap3.BASE, 
                        search_filter=ldap_filter, 
                        attributes=[config_element]
                    )
            result = self.conn.response
            sdn = result[0]['dn']
            js_conf = json.loads(result[0]['attributes'][config_element][0])
            self.apply_persist_changes(js_conf, self.persist_changes[(config_element, config_dn)])
            new_conf = json.dumps(js_conf,indent=4)

            self.conn.modify(
                            sdn, 
                            {config_element: [ldap3.MODIFY_REPLACE, new_conf]}
                            )

        self.conn.search(
                    search_base=dn, 
                    search_scope=ldap3.BASE,
                    search_filter='(objectclass=*)',
                    attributes=self.delete_from_configuration
                    )
        
        result = self.conn.response
        
        remove_list = []
        
        for k in result[0]['attributes']:
            if result[0]['attributes'][k]:
                    self.conn.modify(
                    dn, 
                    {k: [ldap3.MODIFY_DELETE, result[0]['attributes'][k]]}
                    )

        # we need to delete index oxAuthExpiration before restarting opendj
        oxAuthExpiration_index_dn = 'ds-cfg-attribute=oxAuthExpiration,cn=Index,ds-cfg-backend-id=userRoot,cn=Backends,cn=config'
        self.conn.search(
            search_base=oxAuthExpiration_index_dn, 
            search_scope=ldap3.BASE, 
            search_filter='(objectclass=*)', 
            attributes=['ds-cfg-attribute']
            )

        if self.conn.response:        
            self.conn.delete(oxAuthExpiration_index_dn)

        self.conn.unbind()

        # update opendj schema and restart
        self.setupObj.copyFile(
                            os.path.join(self.ces_dir, 'static/opendj/101-ox.ldif'),
                            self.setupObj.openDjSchemaFolder
                            )

        print("Restarting OpenDJ ...")
        self.setupObj.run_service_command('opendj', 'stop')
        self.setupObj.run_service_command('opendj', 'start')

        self.db_connection_ldap()

        if self.sessions_location == 'ldap':
            dn = 'ou=sessions,o=gluu'
            self.conn.search(
                        search_base=dn, 
                        search_scope=ldap3.SUBTREE, 
                        search_filter='(objectClass=*)', 
                        attributes=['*']
                        )
            if self.conn.response:
                for session_entry in self.conn.response:
                    #? delete or modify?
                    #self.conn.delete(session_entry['dn'])
                    if ('oxAuthSessionId' in session_entry['attributes']['objectClass']) and (not 'sid' in session_entry['attributes']):
                        self.conn.modify(
                                    session_entry['dn'], 
                                    {'sid': [ldap3.MODIFY_ADD, str(uuid.uuid4())]}
                                    )
            else:
                print("Adding sessions base entry")
                self.conn.add(dn, attributes={'objectClass': ['top', 'organizationalUnit'], 'ou': ['sessions']})

    def download_apps(self):

        downloads = [
                    ('https://ox.gluu.org/maven/org/gluu/oxtrust-server/{0}{1}/oxtrust-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'identity.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxauth.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxauth-rp/{0}{1}/oxauth-rp-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'oxauth-rp.war')),
                    ('https://ox.gluu.org/maven/org/gluu/fido2-server/{0}{1}/fido2-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'fido2.war')),
                    ('https://ox.gluu.org/maven/org/gluu/scim-server/{0}{1}/scim-server-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'scim.war')),                   
                    ('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/{0}/jetty-distribution-{0}.tar.gz'.format(self.jetty_version), os.path.join(self.app_dir, 'jetty-distribution-{0}.tar.gz'.format(self.jetty_version))),
                    ('https://corretto.aws/downloads/resources/{0}/amazon-corretto-{0}-linux-x64.tar.gz'.format(self.corretto_version), os.path.join(self.app_dir, 'amazon-corretto-11-x64-linux-jdk.tar.gz')),
                    ('https://repo1.maven.org/maven2/org/python/jython-installer/{0}/jython-installer-{0}.jar'.format(self.jython_version), os.path.join(self.app_dir, 'jython-installer-2.7.2.jar')),
                    ('https://raw.githubusercontent.com/GluuFederation/gluu-snap/master/facter/facter', '/usr/bin/facter'),
                    ('https://ox.gluu.org/maven/org/gluufederation/opendj/opendj-server-legacy/4.0.0.gluu/opendj-server-legacy-4.0.0.gluu.zip', os.path.join(self.app_dir, 'opendj-server-4.0.0.zip')),
                    ]

        if os.path.exists('/opt/shibboleth-idp'):
            downloads += [
                    ('https://ox.gluu.org/maven/org/gluu/oxshibbolethIdp/{0}{1}/oxshibbolethIdp-{0}{1}.war'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'idp.war')),
                    ('https://ox.gluu.org/maven/org/gluu/oxShibbolethStatic/{0}{1}/oxShibbolethStatic-{0}{1}.jar'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'shibboleth-idp.jar')),
                    ('https://ox.gluu.org/maven/org/gluu/oxShibbolethKeyGenerator/{0}{1}/oxShibbolethKeyGenerator-{0}{1}.jar'.format(self.up_version, self.build_tag), os.path.join(self.app_dir, 'idp3_cml_keygenerator.jar')),
                    ('https://raw.githubusercontent.com/GluuFederation/oxTrust/master/configuration/src/main/resources/META-INF/shibboleth3/idp/saml-nameid.properties.vm', os.path.join(self.app_dir, 'saml-nameid.properties.vm')),
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
                    ('https://raw.githubusercontent.com/GluuFederation/casa/version_{}/plugins/account-linking/extras/login.xhtml'.format(self.up_version), os.path.join(self.app_dir, 'login.xhtml')),
                    ('https://raw.githubusercontent.com/GluuFederation/casa/version_{}/plugins/account-linking/extras/casa.py'.format(self.up_version), os.path.join(self.app_dir, 'casa.py')),
                    ]

        for download_link, out_file in downloads:
            print("Downloading", download_link)
            self.setupObj.run(['wget', '-nv', download_link, '-O', out_file])

        self.setupObj.run(['chmod', '+x', '/usr/bin/facter'])


    def update_opendj(self):
        
        if not os.path.exists(os.path.join(self.setupObj.ldapBaseFolder,'lib/wrends.jar')):
            print("OpenDJ is up to date.")
            return
        
        if os.path.exists(os.path.join(self.setupObj.ldapBaseFolder, 'config/java.properties')):
            print("Updating OpenDJ")
            print("Stopping OpenDJ")
            self.setupObj.run_service_command('opendj', 'stop')
            print("Extracting OpenDJ")
            self.setupObj.run(['unzip', '-o', '-q', os.path.join(self.app_dir, 'opendj-server-4.0.0.zip'), '-d', '/opt/' ])
            self.setupObj.run(['chown', '-R', 'ldap:ldap', self.setupObj.ldapBaseFolder])
            self.setupObj.fix_opendj_java_properties()
            print("Starting OpenDJ")
            self.setupObj.run_service_command('opendj', 'start')
            self.opendjNeedsUpdate = True

    def update_java(self):
        
        if os.path.isdir('/opt/amazon-corretto-{}-linux-x64'.format(self.corretto_version)):
            print("Java is up to date")
            return

        print ("Upgrading Java")

        cacerts = []

        print("Extracting current cacerts")
        #get host specific certs in current cacerts
        cmd =[self.setupObj.cmd_keytool, '-list', '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit']
        result = self.setupObj.run(cmd)
        for l in result.split('\n'):
            if self.setupObj.hostname in l:
                ls=l.split(', ')
                if ls and (self.setupObj.hostname in ls[0]) and (not 'opendj' in l):
                    alias = ls[0]
                    crt_file = os.path.join(cur_dir, ls[0]+'.crt')
                    self.setupObj.run(['/opt/jre/bin/keytool', '-export', '-alias', alias, '-file', crt_file, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit'])
                    cacerts.append((alias, crt_file))

        for corretto in glob.glob(os.path.join(self.setupObj.distAppFolder,'amazon-corretto-*')):
            if os.path.isfile(corretto):
                print("Deleting", corretto)
                self.setupObj.run(['rm', '-r', corretto])
                

        self.setupObj.copyFile(
                os.path.join(self.app_dir, 'amazon-corretto-11-x64-linux-jdk.tar.gz'), 
                self.setupObj.distAppFolder
                )
 
        for cur_version in glob.glob('/opt/amazon-corretto*'):
            if os.path.isdir(cur_version):
                print("Deleting", cur_version)
                self.setupObj.run(['rm', '-r', cur_version])

        if os.path.islink('/opt/jre'):
            self.setupObj.run(['unlink', '/opt/jre'])

        print("Installing Java")
        self.setupObj.installJRE()

        print("Importing cacerts")
        #import certs        
        for alias, crt_file in cacerts:
            #ensure cert is not exists in keystore
            result = self.setupObj.run(['/opt/jre/bin/keytool', '-list', '-alias', alias, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt'])
            if 'trustedCertEntry' in result:
                self.setupObj.run(['/opt/jre/bin/keytool', '-delete ', '-alias', alias, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt'])

            self.setupObj.run(['/opt/jre/bin/keytool', '-import', '-alias', alias, '-file', crt_file, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt', '-trustcacerts'])

    def update_jython(self):

        #check if jython is up to date
        if os.path.isdir('/opt/jython-{}'.format(self.jython_version)):
            print("Jython is up to date")
            return
        print ("Upgrading Jython")

        for jython in glob.glob(os.path.join(self.setupObj.distAppFolder,'jython-installer-*')):
            if os.path.isfile(jython):
                print("Deleting", jython)
                self.setupObj.run(['rm', '-r', jython])
                

        self.setupObj.copyFile(
                os.path.join(self.app_dir, 'jython-installer-2.7.2.jar'), 
                self.setupObj.distAppFolder
                )
 
        for cur_version in glob.glob('/opt/jython-2*'):
            if os.path.isdir(cur_version):
                print("Deleting", cur_version)
                self.setupObj.run(['rm', '-r', cur_version])

        if os.path.islink('/opt/jython'):
            self.setupObj.run(['unlink', '/opt/jython'])
        
        print("Installing Jython")
        self.setupObj.installJython()

    def update_war_files(self):
        for service in self.setupObj.jetty_app_configuration:
            service_webapps_dir = os.path.join(self.setupObj.jetty_base, service, 'webapps')
            if os.path.exists(service_webapps_dir):
                self.setupObj.copyFile(
                            os.path.join(self.app_dir, service+'.war'),
                            service_webapps_dir
                            )

    def update_jetty(self):
        
        if os.path.isdir('/opt/jetty-9.4/jetty-distribution-{}'.format(self.jetty_version)):
            print("Jetty is up to date")
            return

        print("Upgrading Jetty")
        distAppFolder = self.setupObj.distAppFolder
        self.setupObj.distAppFolder = self.app_dir
        jetty_folder = os.readlink(self.setupObj.jetty_home)
        self.setupObj.run(['unlink', self.setupObj.jetty_home])
        self.setupObj.run(['rm', '-r', '-f', jetty_folder])
        self.setupObj.installJetty()
        self.setupObj.distAppFolder = distAppFolder

    def update_scripts(self):
        print("Updating Scripts")
        if os.path.exists(self.setupObj.gluu_passport_base):
            self.setupObj.enable_scim_access_policy = 'true'

        self.setupObj.prepare_base64_extension_scripts()
        self.setupObj.renderTemplate(self.setupObj.ldif_scripts)
        ldif_scripts_fn = os.path.join(self.setupObj.outputFolder, os.path.basename(self.setupObj.ldif_scripts))
        self.setupObj.logIt("Parsing", ldif_scripts_fn)
        print("Parsing", ldif_scripts_fn)
        self.parser = self.myLdifParser(ldif_scripts_fn)
        self.parser.parse()

        if os.path.exists(self.casa_base_dir):
            self.setupObj.renderTemplate(self.setupObj.ldif_scripts_casa)
            ldif_casa_scripts_fn = os.path.join(self.setupObj.outputFolder, os.path.basename(self.setupObj.ldif_scripts_casa))
            self.setupObj.logIt("Parsing", ldif_casa_scripts_fn)
            print("Parsing", ldif_casa_scripts_fn)
            casa_scripts_parser = self.myLdifParser(ldif_casa_scripts_fn)
            casa_scripts_parser.parse()
            for e in casa_scripts_parser.entries:
                print("Adding casa script", e[0])
                self.parser.entries.append(e)

        getattr(self, 'update_scripts_' + self.default_storage)()

    def update_scripts_couchbase(self):
        for dn, entry in self.parser.entries:
            scr_key = 'scripts_{}'.format(entry['inum'][0])
            print("Updating script:", scr_key)
            result = self.cbm.exec_query('UPDATE `{}` USE KEYS "{}" SET oxScript={}'.format(self.setupObj.couchbase_bucket_prefix, scr_key, json.dumps(entry['oxScript'][0])))
            result_data = result.json()
            print("Result", result_data['status'])
 
    def update_scripts_ldap(self):
        self.db_connection_ldap()
        for dn, entry in self.parser.entries:
            print("Updating script", dn)
            try:
                self.conn.modify(
                    dn, 
                    {'oxScript': [ldap3.MODIFY_REPLACE, entry['oxScript'][0]]}
                    )
            except Exception as e:
                self.conn.add(dn, attributes=entry)

    def update_apache_conf(self):
        print("Updating Apache Configuration")

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

        print("Updadting shibboleth-idp")

        shib_backup_dir = '/opt/shibboleth-idp.back-'+time.strftime("%Y%m%d-%H.%M.%S")

        print("Backing up to", shib_backup_dir)
        
        self.setupObj.copyTree('/opt/shibboleth-idp', shib_backup_dir)
        
        print("Updating idp-metadata.xml")
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
        self.setupObj.copyTree(
                os.path.join(idp_tmp_dir, 'WEB-INF/'), 
                '/opt/shibboleth-idp/webapp',
                overwrite=True
                )

        #Recreate idp-metadata.xml with new format
        temp_fn = os.path.join(self.ces_dir, 'static/idp3/metadata/idp-metadata.xml')
        new_saml_meta_data = self.render_template(temp_fn)
        self.setupObj.writeFile(saml_meta_data_fn, new_saml_meta_data)

        for prop_fn in ('idp.properties', 'ldap.properties', 'services.properties','saml-nameid.properties'):
            print("Updating", prop_fn)
            properties = self.render_template(os.path.join(self.ces_dir, 'static/idp3/conf', prop_fn))
            self.setupObj.writeFile(os.path.join('/opt/shibboleth-idp/conf', prop_fn), properties)

        self.setupObj.copyFile(
                    os.path.join(cur_dir, 'app/saml-nameid.properties.vm'), 
                    '/opt/gluu/jetty/identity/conf/shibboleth3/idp/'
                    )
        self.setupObj.run(['chown', '-R', 'jetty:jetty', '/opt/shibboleth-idp'])
        self.setupObj.run(['rm', '-r', '-f', idp_tmp_dir])

        os.chdir(cur_dir)

    def update_radius(self):

        radius_dir = '/opt/gluu/radius'
        if not os.path.exists(radius_dir):
            return

        print("Updating Gluu Radius Server")
        
        self.setupObj.copyFile(os.path.join(self.ces_dir, 'static/radius/etc/init.d/gluu-radius'), '/etc/init.d')
        self.setupObj.run(['chmod', '+x', '/etc/init.d/gluu-radius'])

        radius_libs = os.path.join(self.app_dir, 'gluu-radius-libs.zip')
        radius_jar = os.path.join(self.app_dir, 'super-gluu-radius-server.jar')

        self.setupObj.run(['unzip', '-o', '-q', radius_libs, '-d', radius_dir ])
        self.setupObj.copyFile(radius_jar, radius_dir)

        self.setupObj.copyFile(os.path.join(self.ces_dir, 'static/radius/etc/default/gluu-radius'), self.setupObj.osDefault)


    def update_oxd(self):
        oxd_root = '/opt/oxd-server/'
        if not os.path.exists(oxd_root):
            return

        print("Updating oxd Server")
        self.setupObj.copyFile(
                    os.path.join(self.app_dir, 'oxd-server.jar'),
                    '/opt/oxd-server/lib'
                    )

        oxd_server_yml_fn = os.path.join(oxd_root, 'conf/oxd-server.yml')
        yml_str = self.setupObj.readFile(oxd_server_yml_fn)
        oxd_yaml = ruamel.yaml.load(yml_str, ruamel.yaml.RoundTripLoader)

        ip = self.setupObj.detect_ip()

        if os.path.exists(self.casa_base_dir) and hasattr(self, 'casa_oxd_host') and getattr(self, 'casa_oxd_host') in (self.setup_prop['hostname'], ip):

            write_oxd_yaml = False
            if 'bind_ip_addresses' in oxd_yaml:
                if not ip in oxd_yaml['bind_ip_addresses']:
                    oxd_yaml['bind_ip_addresses'].append(ip)
                    write_oxd_yaml = True
            else:
                for i, k in enumerate(oxd_yaml):
                    if k == 'storage':
                        break
                else:
                    i = 1
                oxd_yaml.insert(i, 'bind_ip_addresses',  [ip])
                write_oxd_yaml = True

            if write_oxd_yaml:
                yml_str = ruamel.yaml.dump(oxd_yaml, Dumper=ruamel.yaml.RoundTripDumper)
                self.setupObj.writeFile(oxd_server_yml_fn, yml_str)


            #create oxd certificate if not CN=hostname
            r = os.popen('/opt/jre/bin/keytool -list -v -keystore {}  -storepass {} | grep Owner'.format(oxd_yaml['server']['applicationConnectors'][0]['keyStorePath'], oxd_yaml['server']['applicationConnectors'][0]['keyStorePassword'])).read()
            for l in r.splitlines():
                res = re.search('CN=(.*?.),', l)
                if res:
                    cert_cn = res.groups()[0]
                    if cert_cn != self.setup_prop['hostname']:
                        self.setupObj.run([
                            self.setupObj.opensslCommand,
                            'req', '-x509', '-newkey', 'rsa:4096', '-nodes',
                            '-out', '/tmp/oxd.crt',
                            '-keyout', '/tmp/oxd.key',
                            '-days', '3650',
                            '-subj', '/C={}/ST={}/L={}/O={}/CN={}/emailAddress={}'.format(self.setupObj.countryCode, self.setupObj.state, self.setupObj.city, self.setupObj.orgName, self.setupObj.hostname, self.setupObj.admin_email),
                            ])

                        self.setupObj.run([
                            self.setupObj.opensslCommand,
                            'pkcs12', '-export',
                            '-in', '/tmp/oxd.crt',
                            '-inkey', '/tmp/oxd.key',
                            '-out', '/tmp/oxd.p12',
                            '-name', self.setupObj.hostname,
                            '-passout', 'pass:example'
                            ])

                        self.setupObj.run([
                            self.setupObj.cmd_keytool,
                            '-importkeystore',
                            '-deststorepass', 'example',
                            '-destkeypass', 'example',
                            '-destkeystore', '/tmp/oxd.keystore',
                            '-srckeystore', '/tmp/oxd.p12',
                            '-srcstoretype', 'PKCS12',
                            '-srcstorepass', 'example',
                            '-alias', self.setupObj.hostname,
                            ])

                        self.setupObj.backupFile(oxd_yaml['server']['applicationConnectors'][0]['keyStorePath'])
                        self.setupObj.copyFile(
                                '/tmp/oxd.keystore', 
                                oxd_yaml['server']['applicationConnectors'][0]['keyStorePath']
                                )
                        self.setupObj.run(['chown', 'jetty:jetty', oxd_yaml['server']['applicationConnectors'][0]['keyStorePath']])

                        for f in ('/tmp/oxd.crt', '/tmp/oxd.key', '/tmp/oxd.p12', '/tmp/oxd.keystore'):
                            self.setupObj.run(['rm', '-f', f])
                        
            print("Restarting oxd-server")
            self.setupObj.run_service_command('oxd-server', 'stop')
            self.setupObj.run_service_command('oxd-server', 'start')
            time.sleep(5)
            print("Importing oxd certificate to cacerts")        
            self.setupObj.import_oxd_certificate()

    def update_casa(self):
        
        if not os.path.exists(self.casa_base_dir):
            return

        print("Updating casa")
        casa_config_dn = 'ou=casa,ou=configuration,o=gluu'
        casa_config_json = {}
        casa_cors_domains_fn = os.path.join(self.casa_base_dir, 'casa-cors-domains')
        casa_config_json_fn = os.path.join(self.setupObj.configFolder, 'casa.json')

        if os.path.exists(casa_config_json_fn):
            casa_config_json_s = self.setupObj.readFile(casa_config_json_fn)
            casa_config_json = json.loads(casa_config_json_s)

            if os.path.exists(casa_cors_domains_fn):
                casa_cors_domains = self.setupObj.readFile(casa_cors_domains_fn)
                casa_cors_domains_list = [l.strip() for l in casa_cors_domains.splitlines()]
                casa_config_json['allowed_cors_domains'] = casa_cors_domains_list

        casa_plugins_dir = os.path.join(self.casa_base_dir, 'plugins')
        self.setupObj.run_service_command('casa', 'stop')
        
        self.setupObj.copyFile(
                        os.path.join(self.app_dir, 'casa.war'),
                        os.path.join(self.casa_base_dir, 'webapps')
                        )

        account_linking = None
        
        # update plugins
        for plugin in glob.glob(os.path.join(casa_plugins_dir,'*.jar')):
            plugin_zip = zipfile.ZipFile(plugin, "r")
            menifest = plugin_zip.read('META-INF/MANIFEST.MF')
            for l in menifest.splitlines():
                ls = l.decode().strip()
                if ls.startswith('Plugin-Id'):
                    n = ls.find(':')
                    pid = ls[n+1:].strip()
                    if pid in self.casa_plugins:
                        jar_fn = os.path.join(self.app_dir, pid + '.jar')
                        self.setupObj.run(['rm', '-f', plugin])
                        self.setupObj.copyFile(jar_fn, casa_plugins_dir)
                    if pid == 'account-linking':
                        account_linking = True

        if account_linking:
            self.setupObj.copyFile(
                    os.path.join(self.app_dir, 'login.xhtml'),
                    os.path.join(self.setupObj.jetty_base, 'oxauth/custom/pages')
                    )
            
            scr = self.setupObj.readFile(os.path.join(self.app_dir, 'casa.py'))

            if self.default_storage == 'couchbase':
                result = self.cbm.exec_query('UPDATE `{}` USE KEYS "scripts_BABA-CACA" SET oxScript={}'.format(self.setupObj.couchbase_bucket_prefix, json.dumps(scr)))
            elif self.default_storage == 'ldap':
                self.conn.modify(
                        'inum=BABA-CACA,ou=scripts,o=gluu', 
                        {'oxScript':  [ldap3.MODIFY_REPLACE, scr]}
                        )

            if casa_config_json:
                casa_config_json['basic_2fa_settings'] = {
                                    'autoEnable': False,
                                    'allowSelfEnableDisable': True,
                                    'min_creds': casa_config_json['min_creds_2FA']
                                    }

                casa_config_json['plugins_settings'] = {
                                    'strong-authn-settings': {
                                        'policy_2fa' : casa_config_json.get('policy_2fa',''),
                                        'trusted_dev_settings': casa_config_json.get('trusted_dev_settings', {}),
                                        'basic_2fa_settings': casa_config_json['basic_2fa_settings']
                                        }
                                    }

        if casa_config_json:

            casa_config_json_s = json.dumps(casa_config_json, indent=2)

            if self.default_storage == 'ldap':

                
                self.conn.search(
                                search_base=casa_config_dn,
                                search_scope=ldap3.BASE, 
                                search_filter='(objectClass=oxApplicationConfiguration)', 
                                attributes=['oxConfApplication']
                                )

                entry = {'objectClass': ['top', 'oxApplicationConfiguration'], 'ou': ['casa'], 'oxConfApplication': casa_config_json_s}

                if not self.conn.response:
                    print("Importing casa configuration ldif")
                    self.conn.add(casa_config_dn, attributes=entry)
                else:
                    print("Modifying casa configuration ldif")
                    self.conn.modify(
                            casa_config_dn, 
                            {'oxConfApplication':  [ldap3.MODIFY_REPLACE, casa_config_json_s]}
                            )

            else:
                k = 'configuration_casa'
                doc = {'objectClass': 'oxApplicationConfiguration', 'ou': 'casa', 'oxConfApplication': casa_config_json}
                print("Upserting casa configuration document")
                n1ql = 'UPSERT INTO `%s` (KEY, VALUE) VALUES ("%s", %s)' % (self.setupObj.couchbase_bucket_prefix, k, json.dumps(doc))
                self.cbm.exec_query(n1ql)

            self.setupObj.backupFile(casa_config_json_fn)
            #self.setupObj.run(['rm', '-f', casa_config_json_fn])
        
        pylib_dir = os.path.join(self.setupObj.gluuOptPythonFolder, 'libs')
        libdir_base_url = 'https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_{}/static/casa/scripts'.format(self.up_version)
        for casa_lib in glob.glob(os.path.join(pylib_dir, 'casa-external*.py')):
            casa_lib_fn = os.path.basename(casa_lib)
            try:
                response = urllib.request.urlopen(os.path.join('https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_{}/static/casa/scripts'.format(self.up_version), casa_lib_fn))
                if response.code == 200:
                    self.setupObj.backupFile(casa_lib)
                    print ("Updating", casa_lib)
                    target_fn = os.path.join(pylib_dir, casa_lib_fn)
                    scr = response.read()
                    print ("Writing", target_fn)
                    with open(target_fn, 'wb') as w: 
                        w.write(scr)
            except Exception as e:
                print ("ERROR Updating", casa_lib_fn)
                self.setupObj.logIt("ERROR Updating " + casa_lib_fn, True)
                self.setupObj.logIt(str(e), True)

        def fix_oxConfApplication(oxConfApplication):
            if not oxConfApplication.get('oxd_config'):
                oxConfApplication['oxd_config'] = {}
                
            oxConfApplication['oxd_config']['authz_redirect_uri'] = 'https://{}/casa'.format(self.setup_prop['hostname'])
            oxConfApplication['oxd_config']['frontchannel_logout_uri'] = 'https://{}/casa/autologout'.format(self.setup_prop['hostname'])
            oxConfApplication['oxd_config']['post_logout_uri'] = 'https://{}/casa/bye.zul'.format(self.setup_prop['hostname'])

            
            if not oxConfApplication['oxd_config'].get('port'):
                oxConfApplication['oxd_config']['port'] = 8443
            if not oxConfApplication['oxd_config'].get('host'):
                oxConfApplication['oxd_config']['host'] = self.setup_prop['hostname']


        if self.default_storage == 'ldap':
            self.conn.search(
                    search_base=casa_config_dn,
                    search_scope=ldap3.BASE,
                    search_filter='(objectclass=*)', attributes=['oxConfApplication']
                )

            result = self.conn.response

            if result:
                oxConfApplication = json.loads(result[0]['attributes']['oxConfApplication'][0])
                fix_oxConfApplication(oxConfApplication)
                self.conn.modify(
                        casa_config_dn, 
                        {'oxConfApplication':  [ldap3.MODIFY_REPLACE, json.dumps(oxConfApplication)]}
                        )

                self.casa_oxd_host = oxConfApplication['oxd_config']['host']

        else:
            result = self.cbm.exec_query('SELECT oxConfApplication FROM `{}` USE KEYS "configuration_casa"'.format(self.setupObj.couchbase_bucket_prefix))
            if result.ok:
                data = result.json()
                oxConfApplication = data['results'][0]['oxConfApplication']
                self.casa_oxd_host = oxConfApplication['oxd_config']['host']
                fix_oxConfApplication(oxConfApplication)
                n1ql = 'UPDATE `{}` USE KEYS "configuration_casa" SET {}.oxConfApplication={}'.format(self.setupObj.couchbase_bucket_prefix, self.setupObj.couchbase_bucket_prefix, json.dumps(oxConfApplication))
                print("Executing", n1ql)
                self.cbm.exec_query(n1ql)

        self.setupObj.oxd_server_https = 'https://{}:{}'.format(oxConfApplication['oxd_config']['host'], oxConfApplication['oxd_config']['port'])

    def update_passport(self):

        if not os.path.exists(self.setupObj.gluu_passport_base):
            return

        backup_folder = self.setupObj.gluu_passport_base + '_' + self.backup_time

        self.setupObj.run(['mv', self.setupObj.gluu_passport_base, backup_folder])

        print("Updating Passport")
        
        print("Stopping passport server")
        
        self.setupObj.run_service_command('passport', 'stop')

        self.setupObj.run(['mkdir', '-p', self.setupObj.gluu_passport_base])

        print("Extracting passport.tgz into " + self.setupObj.gluu_passport_base) 
        self.setupObj.run(['tar', '--strip', '1', '-xzf', os.path.join(cur_dir, 'app', 'passport.tgz'),
                         '-C', '/opt/gluu/node/passport', '--no-xattrs', '--no-same-owner', '--no-same-permissions'])
    
        print("Extracting passport node modules")
        modules_dir = os.path.join(self.setupObj.gluu_passport_base, 'node_modules')

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

        #create empty log file
        log_file = os.path.join(log_dir, 'start.log')
        open(log_file,'w').close()

        self.setupObj.run(['chown', '-R', 'node:node', '/opt/gluu/node/passport/'])


    def add_oxAuthUserId_pairwiseIdentifier(self):

        print("Adding oxAuthUserId to pairwiseIdentifier.")
        print("This may take several minutes depending on your user number")

        if self.user_location == 'ldap':

            self.conn.search(
                            search_base='ou=people,o=gluu',
                            search_scope=ldap3.SUBTREE, 
                            search_filter='(objectClass=pairwiseIdentifier)', 
                            attributes=['*']
                            )
            result = self.conn.response
            for e in result:
                if not 'oxAuthUserId' in e['attributes']:
                    for dne in dnutils.parse_dn(e['dn']):
                        if dne[0] == 'inum':
                            oxAuthUserId =  dne[1]
                            self.conn.modify(
                                    e['dn'], 
                                    {'oxAuthUserId': [ldap3.MODIFY_ADD, oxAuthUserId]}
                                    )

        else:
            result = self.cbm.exec_query('SELECT META().id AS docid, * from `{}_user` WHERE `objectClass`="pairwiseIdentifier"'.format(self.setupObj.couchbase_bucket_prefix))
            if result.ok:
                data = result.json()
                if data.get('results'):
                    print("Populating oxAuthUserId for pairwiseIdentifier entries. Number of entries: {}".format(len(data['results'])))
                    for user_entry in data['results']:
                        doc = user_entry.get(self.setupObj.couchbase_bucket_prefix+'_user')
                        if doc and not 'oxAuthUserId' in doc:
                            dn = doc['dn']
                            for dnr in dnutils.parse_dn(dn):
                                if dnr[0] == 'inum':
                                    n1ql = 'UPDATE `{}_user` USE KEYS "{}" SET `oxAuthUserId`="{}"'.format(self.setupObj.couchbase_bucket_prefix, user_entry['docid'], dnr[1])
                                    self.cbm.exec_query(n1ql)
                                    break

    def fix_fido2(self):

        self.setupObj.renderTemplate(self.setupObj.fido2_dynamic_conf_json)
        self.setupObj.renderTemplate(self.setupObj.fido2_static_conf_json)

        self.setupObj.templateRenderingDict['fido2_dynamic_conf_base64'] = self.setupObj.generate_base64_ldap_file(self.setupObj.fido2_dynamic_conf_json)
        self.setupObj.templateRenderingDict['fido2_static_conf_base64'] = self.setupObj.generate_base64_ldap_file(self.setupObj.fido2_static_conf_json)
        self.setupObj.renderTemplate(self.setupObj.ldif_fido2)

        self.setupObj.copyFile(self.setupObj.ldif_fido2, '/tmp')
        ldif_fido2 = os.path.join('/tmp', os.path.basename(self.setupObj.ldif_fido2))

        if self.default_storage == 'ldap':
            self.conn.search(
                    search_base='ou=fido2,ou=configuration,o=gluu', 
                    search_scope=ldap3.BASE, 
                    search_filter='(objectClass=*)', 
                    attributes=['*']
                    )
            if not self.conn.response:
                print("Importing fido2 configuration ldif")
                self.setupObj.import_ldif_opendj([ldif_fido2])

        else:
            result = self.cbm.exec_query('SELECT gluuConfStatic FROM `{}` USE KEYS "configuration_fido2"'.format(self.setupObj.couchbase_bucket_prefix))
            if result.ok:
                data = result.json()
                if not data.get('results'):
                    print("Importing fido2 configuration ldif")
                    self.setupObj.import_ldif_couchebase([ldif_fido2])

        if self.user_location == 'ldap':
            self.conn.search(
                        search_base='ou=people,o=gluu', 
                        search_scope=ldap3.SUBTREE, 
                        search_filter='(objectclass=oxDeviceRegistration)', 
                        attributes=['*']
                        )

            result = self.conn.response
            if result:
                print("Populating personInum for fido2 entries. Number of entries: {}".format(len(result)))
                for entry in result:
                    dn = entry['dn']
                    if not 'personInum' in entry['attributes']:
                        for dnr in dnutils.parse_dn(dn):
                            if dnr[0] == 'inum':
                                inum = dnr[1]
                                self.conn.modify(
                                        dn, 
                                        {'personInum': [ldap3.MODIFY_ADD, inum]}
                                        )
                                break

        else:
            result = self.cbm.exec_query('SELECT META().id AS docid, * from `{}_user` WHERE `objectClass`="oxDeviceRegistration"'.format(self.setupObj.couchbase_bucket_prefix))
            if result.ok:
                data = result.json()
                if data.get('results'):
                    print("Populating personInum for fido2 entries. Number of entries: {}".format(len(data['results'])))
                    for user_entry in data['results']:
                        doc = user_entry.get(self.setupObj.couchbase_bucket_prefix+'_user')
                        if doc and not 'personInum' in doc:
                            dn = doc['dn']
                            for dnr in dnutils.parse_dn(dn):
                                if dnr[0][0] == 'inum':
                                    print((user_entry['docid']))
                                    n1ql = 'UPDATE `{}_user` USE KEYS "{}" SET `personInum`="{}"'.format(self.setupObj.couchbase_bucket_prefix, user_entry['docid'], dnr[1])
                                    self.cbm.exec_query(n1ql)
                                    break

    def updateAttributes(self):

        attributes_ldif_fn = os.path.join(self.ces_dir, 'templates/attributes.ldif')
        attributes_ldif = self.myLdifParser(attributes_ldif_fn)
        attributes_ldif.parse()

        if self.default_storage == 'ldap':
            dn = 'inum=6049,ou=attributes,o=gluu'
            self.conn.search(
                    search_base=dn, 
                    search_scope=ldap3.BASE, 
                    search_filter='(objectClass=*)', 
                    attributes=['*']
                    )
            result = self.conn.response
            if not 'user_permission' in result[0]['attributes'].get('oxAuthClaimName', []):
                print("Modifying attribute", dn)
                self.conn.modify(
                            dn,
                            {'oxAuthClaimName': [ldap3.MODIFY_ADD, 'user_permission']}
                            )

            self.conn.search(
                    search_base='ou=attributes,o=gluu', 
                    search_scope=ldap3.LEVEL, 
                    search_filter='(objectClass=*)', 
                    attributes=['inum']
                    )
            result = self.conn.response

            current_attributes_list = [ e['dn'] for e in result ]

            for dn, entry in attributes_ldif.entries:
                if not dn in current_attributes_list:
                    print("Adding attribute", dn)
                    self.conn.add(dn, attributes=entry)

        elif self.default_storage == 'couchbase':
            result = self.cbm.exec_query('SELECT oxAuthClaimName FROM `{}` USE KEYS "attributes_6049"'.format(self.setupObj.couchbase_bucket_prefix))
            data = result.json()

            if not 'user_permission' == data.get('results')[0].get('oxAuthClaimName',''):
                n1ql = 'UPDATE `{0}` USE KEYS "attributes_6049" SET {0}.oxAuthClaimName="user_permission"'.format(self.setupObj.couchbase_bucket_prefix)
                print("Executing", n1ql)
                result = self.cbm.exec_query(n1ql)

            documents = self.get_documents_from_ldif(attributes_ldif_fn)
            for k, doc in documents:
                result = self.cbm.exec_query('SELECT inum FROM `{}` USE KEYS "{}"'.format(self.setupObj.couchbase_bucket_prefix, k))
                if not result.json().get('results'):
                    print("Adding attribute", k)
                    n1ql = 'UPSERT INTO `%s` (KEY, VALUE) VALUES ("%s", %s)' % (self.setupObj.couchbase_bucket_prefix, k, json.dumps(doc))
                    self.cbm.exec_query(n1ql)


    def update_scopes(self):

        ldif_fn = os.path.join(self.ces_dir, 'templates/scopes.ldif')
        ldif_parser = self.myLdifParser(ldif_fn)
        ldif_parser.parse()
        
        if self.default_storage == 'ldap':
            self.db_connection_ldap()
            for dn, entry in ldif_parser.entries:
                self.conn.search(
                            search_base=dn, 
                            search_scope=ldap3.BASE, 
                            search_filter='(objectClass=*)', 
                            attributes=['*']
                            )
                if not self.conn.response:
                    print("Adding scope", dn)
                    self.conn.add(dn, attributes=entry)
        else:
            documents = self.get_documents_from_ldif(ldif_fn)
            for k, doc in documents:
                result = self.cbm.exec_query('SELECT inum FROM `{}` USE KEYS "{}"'.format(self.setupObj.couchbase_bucket_prefix, k))
                if not result.json().get('results'):
                    print("Adding scope", k)
                    n1ql = 'UPSERT INTO `%s` (KEY, VALUE) VALUES ("%s", %s)' % (self.setupObj.couchbase_bucket_prefix, k, json.dumps(doc))
                    self.cbm.exec_query(n1ql)

    def update_default_settings(self):
        print("Updating /etc/default files")
        self.setupObj.jetty_dist = '/opt/jetty-' + '.'.join(self.jetty_version.split('.')[:2])
        for service in ('casa', 'fido2', 'identity', 'idp', 'oxauth', 'oxauth-rp', 'scim'):
            default_fn = os.path.join('/etc/default', service)
            print("Updating default file", service)
            if os.path.exists(default_fn):
                default_ = self.render_template(os.path.join(self.ces_dir, 'templates/jetty', service))
                self.setupObj.writeFile(default_fn, default_)

updaterObj = GluuUpdater()
updaterObj.download_ces()
updaterObj.prepare_persist_changes()
updaterObj.download_apps()
updaterObj.determine_persistence_type()
updaterObj.update_default_settings()
updaterObj.stop_services()
updaterObj.update_java()
updaterObj.update_opendj()
if not updaterObj.opendjNeedsUpdate:
    updaterObj.setupObj.fix_opendj_java_properties()
updaterObj.update_jython()
updaterObj.update_scopes()
updaterObj.updateAttributes()
updaterObj.fix_gluu_config()
updaterObj.update_persistence_data()
updaterObj.update_jetty()
updaterObj.update_war_files()
updaterObj.update_scripts()
updaterObj.update_apache_conf()
updaterObj.update_shib()
updaterObj.update_passport()
updaterObj.update_radius()
updaterObj.update_casa()
updaterObj.update_oxd()
updaterObj.add_oxAuthUserId_pairwiseIdentifier()
updaterObj.fix_fido2()

updaterObj.setupObj.deleteLdapPw()

print()
for msg in updaterObj.postmessages:
    print("*", msg)
print()
print("Please logout from container and restart Gluu Server")

