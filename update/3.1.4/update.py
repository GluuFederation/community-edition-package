#!/usr/bin/python

import os
import time
import glob
import re
import shutil
import json
import base64
import sys
import uuid
import io
import platform
import uuid
import random
import string

import xml.etree.ElementTree as ET

from pyDes import *

package_type = None

if os.path.exists('/etc/yum.repos.d/'):
    package_type = 'rpm'
elif os.path.exists('/etc/apt/sources.list'):
    package_type = 'deb'

missing_packages = []

if not os.path.exists('/usr/bin/zip'):
    missing_packages.append('zip')

if not os.path.exists('/usr/bin/unzip'):
    missing_packages.append('unzip')
    
try:
    import ldap
except:
    missing_packages.append('python-ldap')
    

if missing_packages:
    
    packages_str = ' '.join(missing_packages)
    result = raw_input("Missing package(s): {0}. Install now? (Y|n): ".format(packages_str))
    if result.strip() and result.strip().lower()[0] == 'n':
        sys.exit("Can't continue without installing these packages. Exiting ...")

    if package_type == 'rpm':
        cmd = "yum install -y {0}".format(packages_str)
    else:
        cmd = "apt-get install -y {0}".format(packages_str)

    print "Installing package(s) with command: "+ cmd
    os.system(cmd)

import ldap
import ldap.modlist as modlist
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
from ldap.schema import ObjectClass


result = raw_input("Starting upgrade. CONTINUE? (y|N): ")
if not result.strip() or (result.strip() and result.strip().lower()[0] != 'y'):
    print "You can re-run this script to upgrade. Bye now ..."
    sys.exit()

msg = """Would you like to replace all the default Gluu Server scripts for 3.1.4?
(This will replace any customization you may have made to these default script entries)
(Y|n)"""
repace_scripts = False
result = raw_input(msg)
if not result.strip() or result.strip().lower()[0] == 'y':
    repace_scripts = True

print "Starting Upgrade..."

def parse_setup_properties(prop_file='/install/community-edition-setup/setup.properties.last'):
    setup_prop = dict()
    content = open(prop_file).readlines()
    for l in content:
        ls = l.strip()
        if ls:
            if not ls[0] == '#':
                eq_loc = ls.find('=')

                if eq_loc > 0:
                    k = ls[:eq_loc]
                    v = ls[eq_loc+1:]
                    v=v.replace('\\=','=')
                    v=v.replace("\\'","'")
                    v=v.replace('\\"','"')
                    if v == 'True':
                        v = True
                    elif v == 'False':
                        v = False
                    setup_prop[k] = v

    return setup_prop

def getQuad():
    return str(uuid.uuid4())[:4].upper()

def getPW(size=12, chars=string.ascii_uppercase + string.digits + string.lowercase):
        return ''.join(random.choice(chars) for _ in range(size))

def obscure(data, encode_salt):
    engine = triple_des(encode_salt, ECB, pad=None, padmode=PAD_PKCS5)
    data = data.encode('ascii')
    en_data = engine.encrypt(data)
    return base64.b64encode(en_data)


def get_ldap_admin_serevers_password():
    salt_file = open('/etc/gluu/conf/salt').read()
    salt = salt_file.split('=')[1].strip()
    ox_ldap_properties_file = '/etc/gluu/conf/ox-ldap.properties'
    
    for l in open(ox_ldap_properties_file):
        if l.startswith('bindPassword'):
            s = l.split(':')[1].strip()
            engine = triple_des(salt, ECB, pad=None, padmode=PAD_PKCS5)
            cipher = triple_des(salt)
            decrypted = cipher.decrypt(base64.b64decode(s), padmode=PAD_PKCS5)
            passwd = decrypted
        elif l.startswith('servers'):
            s = l.split(':')[1].strip()
            servers_s = s.split(',')
            servers = [ ss.split(':')[0] for ss in servers_s ]
            
            
    return passwd, servers

def get_saml_certs(cfn):
    tree = ET.parse(cfn)
    root = tree.getroot()
    cert_elems = []
    for elem in root.iter():
        if elem.tag.endswith('KeyDescriptor'):
            cert_elems.append(elem)

    certs = {}

    for elem in cert_elems:
        cert_use = elem.get('use')
        for subelem in elem.iter():
            if  subelem.tag.endswith('X509Certificate'):
                certs[cert_use] = subelem.text.strip()

    return certs

def fomatWithDict(text, dictionary):
    text = re.sub(r"%([^\(])", r"%%\1", text)
    text = re.sub(r"%$", r"%%", text)  # There was a % at the end?

    return text % dictionary


from ldif import LDIFParser

class MyLdif(LDIFParser):
    def __init__(self, ldif):
        LDIFParser.__init__(self, ldif)
        self.entries = []

    def handle(self, dn, entry):
        entry_s = {}
        for k in entry:
            val_s = [ str(v) for v in entry[k] ]
            entry_s[str(k)] = val_s

        self.entries.append((dn, entry_s))

    def getDn(self, dn):
        for e in self.entries:
            if e[0] == dn:
                return e[1]


class GluuUpdater:
    def __init__(self):
        self.gluu_version = '3.1.4'
        self.update_version = self.gluu_version + 'upg'
        self.update_dir = os.path.join('/opt/upd/', self.update_version)
        self.app_dir = os.path.join(self.update_dir,'app')
        self.setup_properties = parse_setup_properties()
        self.inumOrg = self.setup_properties['inumOrg']

        self.gluu_app_dir = '/opt/gluu/jetty'
        self.update_temp_dir = os.path.join(self.app_dir,'temp')
        self.passport_mdules_archive = os.path.join(self.app_dir, 'passport-version_{0}-node_modules.tar.gz'.format(self.gluu_version))
        self.saml_meta_data = '/opt/shibboleth-idp/metadata/idp-metadata.xml'
        self.extensionFolder = os.path.join(self.app_dir, 'extension')
        self.scripts_ldif = os.path.join(self.update_temp_dir, 'scripts.ldif')
        self.passport_config = os.path.join(self.update_temp_dir, 'passport-config.json')


        if self.setup_properties.has_key('currentGluuVersion'):
            self.cur_version = self.setup_properties['currentGluuVersion']
        elif self.setup_properties.has_key('version'):
            self.cur_version = self.setup_properties['version']
        elif self.setup_properties.has_key('oxVersion'):
            self.cur_version = re.search('(\d+.\d+.\d+)', self.setup_properties['oxVersion']).group()
        else:
            self.cur_version = '1.1.1'

        print "Current Gluu Server version", self.cur_version


        self.setup_properties['shibboleth_version'] = 'v3'

        if self.setup_properties.get('ldap_type'):
            self.ldap_type = self.setup_properties['ldap_type']
        else:
            self.ldap_type = 'openldap'
    
        
        
        if self.ldap_type == 'opendj':
            self.ldap_bind_dn = self.setup_properties['opendj_ldap_binddn']
        elif self.ldap_type == 'openldap':
            self.ldap_bind_dn = self.setup_properties['ldap_binddn']
            
        self.ldap_bind_pw, self.ldap_servers = get_ldap_admin_serevers_password()
        
        self.ldap_host = self.ldap_servers[0]
        
        self.inumOrg = self.setup_properties['inumOrg']
        self.hostname = self.setup_properties['hostname'] 
        self.backup_time = time.strftime('%Y-%m-%d.%H:%M:%S')
        self.backup_folder = '/opt/upd/{0}/backup_{1}'.format(self.update_version, self.backup_time)


        p = platform.linux_distribution()
        self.os_type = p[0].split()[0].lower()
        self.os_version = p[1].split('.')[0]

        
        if not os.path.exists(self.backup_folder):
            os.mkdir(self.backup_folder)

    def checkRemoteSchema(self):
        result = self.conn.search_s('cn=schema',ldap.SCOPE_BASE,'(objectclass=*)',['objectClasses'])
        for obj_s in result[0][1]['objectClasses']:
            obj = ObjectClass(obj_s)
            if  'oxCacheEntity' in obj.names:
                return True


    def ldappConn(self):
        for i in range(5):
            try:
                self.conn = ldap.initialize('ldaps://{0}:1636'.format(self.ldap_host))
                self.conn.simple_bind_s(self.ldap_bind_dn, self.ldap_bind_pw)
                return
            except:
                print "Can't connect to LDAP Server. Retrying in 5 secs ..."
                time.sleep(5)
                
        sys.exit("Max retry reached. Exiting...")
        
        

    def updateWar(self):

        new_war_dir = os.path.join(self.update_dir, 'war')
        for app in os.listdir(self.gluu_app_dir):
            war_app = app+'.war'
            new_war_app_file = os.path.join(new_war_dir, war_app)
            if os.path.exists(new_war_app_file):
                app_dir = os.path.join(self.gluu_app_dir, app, 'webapps')
                cur_war = os.path.join(app_dir, war_app)
                if os.path.exists(cur_war):
                    print "Backing up", war_app, "to", self.backup_folder
                    shutil.copy(cur_war, self.backup_folder)
                    
                    resources_dir = os.path.join(self.gluu_app_dir, app, 'resources')
                    if not os.path.exists(resources_dir):
                        os.mkdir(resources_dir)
                    os.system('chown jetty:jetty ' + resources_dir)
                    
                print "Updating", war_app
                shutil.copy(new_war_app_file, app_dir)

        shutil.copy('/opt/dist/gluu/idp3_cml_keygenerator.jar', self.backup_folder)
        shutil.copy(os.path.join(self.app_dir, 'idp3_cml_keygenerator.jar'), '/opt/dist/gluu/')
        
    # TODO: Do we still need this?
    def updateOxAuthConf(self):

        if self.cur_version >= '3.1.3':
            return

        result = self.conn.search_s('ou=appliances,o=gluu',ldap.SCOPE_SUBTREE,'(objectClass=oxAuthConfiguration)',['oxAuthConfDynamic'])

        dn = result[0][0]
        oxAuthConfDynamic = json.loads(result[0][1]['oxAuthConfDynamic'][0])

        json_update = False

        if not 'umaResourceLifetime' in oxAuthConfDynamic: 
            oxAuthConfDynamic['umaResourceLifetime'] = 2592000
            json_update = True
            
        if not 'authorizationRequestCustomAllowedParameters' in oxAuthConfDynamic: 
            oxAuthConfDynamic['authorizationRequestCustomAllowedParameters'] = []
            json_update = True

        if not 'legacyDynamicRegistrationScopeParam' in oxAuthConfDynamic: 
            oxAuthConfDynamic['legacyDynamicRegistrationScopeParam'] = False
            json_update = True

        if not 'useCacheForAllImplicitFlowObjects' in oxAuthConfDynamic: 
            oxAuthConfDynamic['useCacheForAllImplicitFlowObjects'] = False
            json_update = True

        if not 'umaGrantAccessIfNoPolicies' in oxAuthConfDynamic: 
            oxAuthConfDynamic['umaGrantAccessIfNoPolicies'] = True
            json_update = True

        if not 'corsConfigurationFilters' in oxAuthConfDynamic:
            oxAuthConfDynamic['corsConfigurationFilters'] = [{"filterName": "CorsFilter", "corsAllowedOrigins": "*", "corsAllowedMethods": "GET,POST,HEAD,OPTIONS", "corsAllowedHeaders": "Origin,Authorization,Accept,X-Requested-With,Content-Type,Access-Control-Request-Method,Access-Control-Request-Headers", "corsExposedHeaders": "", "corsSupportCredentials": True, "corsLoggingEnabled": False, "corsPreflightMaxAge": 1800, "corsRequestDecorate": True}]
            json_update = True

        if json_update:
            jsons = json.dumps(oxAuthConfDynamic)
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxAuthConfDynamic',  jsons)])
            print 'oxAuthConfDynamic updated'
        else:
            print 'No need to update oxAuthConfDynamic'


    def addUserCertificateMetadata(self):
        if self.cur_version >= '3.1.3':
            return

        result=self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'(&(objectClass=gluuAttribute)(gluuAttributeName=userCertificate))')
        if not result:
            dn = 'inum={0}!0005!CACA,ou=attributes,o={0},o=gluu'.format(self.inumOrg)
            entry = {
                    'displayName': ['User certificate'],
                    'description': ['User certificate'],
                    'gluuStatus': ['active'],
                    'objectClass': ['gluuAttribute', 'top'],
                    'urn': ['urn:mace:dir:attribute-def:userCertificate'],
                    'oxValidation': ['{"minLength":null,"maxLength":2048,"regexp":""}'],
                    'gluuAttributeEditType': ['admin', 'user'],
                    'gluuAttributeOrigin': ['gluuPerson'],
                    'gluuAttributeViewType': ['admin', 'user'],
                    'inum': ['{0}!0005!CACA'.format(self.inumOrg)],
                    'gluuAttributeType': ['certificate'],
                    'gluuAttributeName': ['userCertificate']
                 }
                
            result = self.conn.add_s(dn, modlist.addModlist(entry))
        else:
            print "No need to add certificate metadata"

    def fixAttributeTypes(self):
        if self.cur_version >= '3.1.3':
            return

        new_attrib_types = (
                    ('emailVerified', 'boolean'),
                    ('phoneNumberVerified', 'boolean'),
                    ('updatedAt', 'generalizedTime'),
                    ('picture', 'binary'),
                    )

        for attr, atype in new_attrib_types:
            s_filter = '(&(objectClass=gluuAttribute)(gluuAttributeName={0}))'.format(attr)
            result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE, s_filter, ['gluuAttributeType'])
            dn = result[0][0]
            entry = result[0][1]['gluuAttributeType']
            if not entry[0] == atype:
                self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'gluuAttributeType',  atype)])
                print dn, 'modified'
            else:
                print 'No need to modify'


    def addOxAuthClaimName(self):
        if self.cur_version >= '3.1.3':
            return

        dn = 'inum={0}!0005!D2E0,ou=attributes,o={0},o=gluu'.format(self.inumOrg)
        result = self.conn.search_s(dn,  ldap.SCOPE_BASE, attrlist=['oxAuthClaimName'])
        if not result[0][1]:
            self.conn.modify_s(dn, [( ldap.MOD_ADD, 'oxAuthClaimName',  ['member_of'])]) 
            print dn, 'modified'

        print dn, "not modified"

    def modifySectorIdentifiers(self):
        if self.cur_version >= '3.1.3':
            return

        sector_identifiers = 'ou=sector_identifiers,o={0},o=gluu'.format(self.inumOrg)        
        result = self.conn.search_s(sector_identifiers, ldap.SCOPE_SUBTREE)
        for dn, entry in result:
            if  dn.startswith('inum='):
                dn_s = ldap.dn.str2dn(dn)
                newrdn = 'oxId={0}'.format(dn_s[0][0][1])
                self.conn.rename_s(dn, newrdn)

    def copyFiles(self):
        if self.cur_version >= '3.1.3':
            return

        for f in ('/opt/gluu/jetty/oxauth/custom/i18n', '/opt/gluu/jetty/identity/custom/i18n'):
            os.system('mkdir -p {0}'.format(f))
            os.system('chown jetty:jetty {0}'.format(f))

        if os.path.exists('/install/community-edition-setup/output/jetty/oxauth_web_resources.xml'):
            os.system('cp /install/community-edition-setup/output/jetty/oxauth_web_resources.xml /opt/gluu/jetty/oxauth/webapps')
        if os.path.exists('/install/community-edition-setup/output/jetty/identity_web_resources.xml'):
            os.system('cp /install/community-edition-setup/output/jetty/identity_web_resources.xml  /opt/gluu/jetty/identity/webapps')
        

    # TODO: Do we still need this?
    def checkIdpMetadata(self):
        idp_meatdata_file = '/opt/shibboleth-idp/metadata/idp-metadata.xml'
        print "checking {0}".format(idp_meatdata_file)
        
        if os.path.exists(idp_meatdata_file):
            change_str = 'https://ce.gluu.info/idp/profile/SAML2/SOAP/ArtifactResolution'
            to_str = 'https://{0}/idp/profile/SAML2/SOAP/ArtifactResolution'.format(self.hostname)
            f = open(idp_meatdata_file).read()
            if change_str in f:
                f = f.replace(change_str, to_str)
                os.system('cp {0} {0}.bak'.format(idp_meatdata_file))
                with open(idp_meatdata_file,'w') as w:
                    w.write(f)
    
            
    def upgradeJetty(self):

        print "Updating jetty"
        
        jetty_re = re.compile('jetty-distribution-(\d+).(\d+).(\d+).(.+)')

        cur_ver = glob.glob("/opt/jetty-9.*/jetty-distribution*")[0]

        rss = jetty_re.search(os.path.basename(cur_ver)).groups()
        cur_folder = '/opt/jetty-{0}.{1}'.format(rss[0], rss[1])

        new_ver = max(glob.glob(os.path.join(self.update_dir, 'app/jetty-distribution*')))

        rss = jetty_re.search(os.path.basename(new_ver)).groups()
        new_folder = '/opt/jetty-{0}.{1}'.format(rss[0], rss[1])

        if not os.path.exists(new_folder):
            os.mkdir(new_folder)

        os.system('tar -xf {0} -C {1}'.format(new_ver, new_folder))

        os.system('unlink /opt/jetty')
        jetty_base_name = os.path.basename(new_ver)
        os.system('ln -sf {0}/{1} /opt/jetty'.format(new_folder,jetty_base_name[:-7]))
        os.system('chown -h jetty:jetty /opt/jetty')

        cur_temp_s = 'TMPDIR={0}/temp'.format(cur_folder)
        new_temp_s = 'TMPDIR={0}/temp'.format(new_folder)
        
        for fn in glob.glob('/etc/default/*'):
            f = open(fn).read()
            if cur_temp_s in f:
                f = f.replace(cur_temp_s, new_temp_s)
                with open(fn,'w') as w:
                    w.write(f)
                    
        for fn in glob.glob('/opt/gluu/jetty/*/start.ini'):
            f = open(fn).readlines()
            wf = False
            for i in range(len(f)):
                if f[i].startswith('--module=logging'):
                    wf = True
                    f[i] = '--module=console-capture\n'
            if wf:
                with open(fn,'w') as w:
                    w.write(''.join(f))

        if not os.path.exists('/opt/jetty-9.4/temp'):
            os.mkdir('/opt/jetty-9.4/temp')
            
        os.system('chown -R jetty:jetty /opt/jetty-9.4/')


    def updateLdapSchema(self):
        
        if self.ldap_host != 'localhost':
            self.ldappConn()
            if self.ldap_host != 'localhost':
                if not self.checkRemoteSchema():
                    cprint ("LDAP server seems on remote server. Please copy content of \n"
                        "/opt/upd/3.1.4upg/ldap/opendj (from the machine you are \n"
                        "running this script) to /opt/opendj/config/schema \n"
                        "(on remote opendj server) and restart opendj"
                        )
                    s=raw_input("Please update schema and hit <ENTER> key")
                while True:
                    self.ldappConn()
                    if self.checkRemoteSchema():
                        break
                    else:
                        print("LDAP Server with new schema is not ready.\n")
                        s=raw_input("Please update schema and hit <ENTER> key")
                        
            return

        if self.cur_version >= '3.1.4':
            return
        
        print "Updating ldap schema"
        
        print "Stopping LDAP Server"
        if self.ldap_type == 'openldap':
            os.system('/etc/init.d/solserver stop')
        else:
            os.system('/etc/init.d/opendj stop')
        
        #wait 5 secs for ldap server to stop
        time.sleep(5)
        
        if self.ldap_type == 'openldap':
            ldap_schema_dir = '/opt/gluu/schema/openldap'
            new_schema_list = [ os.path.join(self.update_dir, 'ldap/openldap/gluu.schema') ]
            cur_schema_list = [os.path.join(ldap_schema_dir, 'gluu.schema')]
            
        elif self.ldap_type == 'opendj':
            ldap_schema_dir = '/opt/opendj/config/schema'
            new_schema_list = [os.path.join(self.update_dir, 'ldap/opendj/101-ox.ldif'), os.path.join(self.update_dir, 'ldap/opendj/96-eduperson.ldif')]
            cur_schema_list = [os.path.join(ldap_schema_dir, '101-ox.ldif')]
    
        for cur_schema in cur_schema_list:
            print cur_schema
            if os.path.exists(cur_schema):
                print "Backing up", cur_schema
                shutil.move(cur_schema, self.backup_folder)
        
        for new_schema in new_schema_list:
            print "Copying new_schema", new_schema
            shutil.copy(new_schema, ldap_schema_dir)
            os.system('chown ldap:ldap {0}'.format(cur_schema))

        print "Starting LDAP Server"
        #After updateting schema we need to restart ldap server
        if self.ldap_type == 'openldap':
            os.system('/etc/init.d/solserver start')
        else:
            os.system('/etc/init.d/opendj start')
        #wait 10 secs for ldap server to start
        time.sleep(10)


    def updatePassport(self):
        if not os.path.exists('/opt/gluu/node/passport'):
            return
            
        print "Updating Passport"
        os.system('service passport stop')

        passport_config_fn = '/etc/gluu/conf/passport-config.json'

        shutil.copy(passport_config_fn, self.backup_folder)
        cur_config = json.loads(open(passport_config_fn).read())

        self.setup_properties['passport_rp_client_cert_alias'] = cur_config['keyId']

        tmp = open(self.passport_config).read()
        conf = tmp % self.setup_properties

        with open(passport_config_fn,'w') as w:
            w.write(conf)

        passportArchive = os.path.join(self.update_dir+'/app/passport.tgz')
                
        backup_folder = '/opt/upd/{0}/backup_passport_{1}'.format(self.update_version,self.backup_time)
        
        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)

        backup_file = os.path.join(backup_folder, 'passport-package-v313-backup.tar.gz')
        os.system('tar -cpzf {0} --one-file-system /opt/gluu/node/passport/'.format(backup_file))

        if not os.path.exists('/opt/gluu/node/passport'):
            os.mkdir('/opt/gluu/node/passport')

        print "Extracting passport.tgz into /opt/gluu/node/passport"
        os.system('tar --strip 1 -xzf {0} -C /opt/gluu/node/passport --no-xattrs --no-same-owner --no-same-permissions'.format(passportArchive))

        modules_target_dir = '/opt/gluu/node/passport/node_modules'
 
        print "Extracting passport node modules"
        
        os.system('tar --strip 1 -xzf {0} -C /opt/gluu/node/passport/node_modules --no-xattrs --no-same-owner --no-same-permissions'.format(self.passport_mdules_archive))

        saml_config = os.path.join(self.update_dir, 'app', 'passport-saml-config.json')
        os.system('cp {0} /etc/gluu/conf'.format(saml_config))
        os.system('chown node:node /etc/gluu/conf/passport-saml-config.json')
        
        log_dir = '/opt/gluu/node/passport/server/logs'

        if not os.path.exists(log_dir): 
            os.mkdir(log_dir)

        if not os.path.exists('/opt/gluu/node/passport/server/utils/misc.js'):
            open('/opt/gluu/node/passport/server/utils/misc.js','w')


        os.system('chown -R node:node /opt/gluu/node/passport')

        inum = '%(inumOrg)s!2FDB.CF02' % self.setup_properties
        result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'inum={0}'.format(inum))

        dn=result[0][0]

        oxConfigurationProperty_list = [ 
                            {"value1":"key_store_file","value2":"/etc/certs/passport-rp.jks","hide":False,"description":""},
                            {"value1":"key_store_password","value2":"secret","hide":False,"description":""},
                            {"value1":"behaviour","value2":"social","hide":False,"description":""},
                        ]


        for oxc in result[0][1]['oxConfigurationProperty']:
            oxcjs = json.loads(oxc)

            for new_oxc in oxConfigurationProperty_list[:]:
                if new_oxc['value1'] == oxcjs['value1']:
                    oxConfigurationProperty_list.remove(new_oxc)
                    break


        if oxConfigurationProperty_list:
            oxConfigurationProperty=result[0][1]['oxConfigurationProperty'][:]

            for oxc in oxConfigurationProperty_list:
                oxConfigurationProperty.append(json.dumps(oxc))

            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxConfigurationProperty',  oxConfigurationProperty)])


        inum = '%(inumOrg)s!D40C.1CA4' % self.setup_properties
        result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'inum={0}'.format(inum))
        
        if result:

            dn = result[0][0]
            entry = result[0][1]

            oxConfigurationProperty_list = [ {"value1":"behaviour","value2":"saml","hide":False,"description":""},
                    {"value1":"key_store_file","value2":"/etc/certs/passport-rp.jks","hide":False,"description":""},
                    {"value1":"key_store_password","value2":"secret","hide":False,"description":""}
                    ]

            for oxc in result[0][1]['oxConfigurationProperty']:
                oxcjs = json.loads(oxc)

                for new_oxc in oxConfigurationProperty_list[:]:
                    if new_oxc['value1'] == oxcjs['value1']:
                        oxConfigurationProperty_list.remove(new_oxc)
                        break
                    
            if oxConfigurationProperty_list:
                oxConfigurationProperty=result[0][1]['oxConfigurationProperty'][:]

                for oxc in oxConfigurationProperty_list:
                    oxConfigurationProperty.append(json.dumps(oxc))

                self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxConfigurationProperty',  oxConfigurationProperty)])

        else:

            dn = 'inum=%(inumOrg)s!D40C.1CA4,ou=scripts,o=%(inumOrg)s,o=gluu' % self.setup_properties
            attrs = {
                    'objectClass': ['oxCustomScript', 'top'],
                    'description': 'Passport SAML authentication module',
                    'displayName': 'passport_saml',
                    'gluuStatus': 'false',
                    'inum': '%(inumOrg)s!D40C.1CA4' % self.setup_properties,
                    'oxConfigurationProperty': ['{"value1":"generic_remote_attributes_list","value2":"username, email, name, name, givenName, familyName, provider","description":""}',
                                                '{"value1":"generic_local_attributes_list","value2":"uid, mail, cn, displayName, givenName, sn, provider","description":""}',
                                                '{"value1":"behaviour","value2":"saml","hide":false,"description":""}'
                                                '{"value1":"key_store_file","value2":"/etc/certs/passport-rp.jks","hide":false,"description":""}',
                                                '{"value1":"key_store_password","value2":"secret","hide":false,"description":""}',
                                               ],
                    'oxLevel': '50',
                    'oxModuleProperty': ['{"value1":"usage_type","value2":"interactive","description":""}',
                                         '{"value1":"location_type","value2":"ldap","description":""}'
                                        ],
                    'oxRevision': '1',
                    'oxScript': oxScript,
                    'oxScriptType': 'person_authentication',
                    'programmingLanguage': 'python'
                }


            ldif = modlist.addModlist(attrs)
            self.conn.add_s(dn,ldif)

        inum = '%(inumOrg)s!0011!2DAF.F9A5' % self.setup_properties
        result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'inum={0}'.format(inum))

        if result:
            dn=result[0][0]
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'displayName',  'scim_access_policy')])
    
        if self.cur_version < '3.1.3':
            #convert passport strategies to new style
            result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'(objectClass=oxPassportConfiguration)')
            if result:
                dn = result[0][0]
                new_strategies = {}
                strategies = []
                change = False
                for pp_conf in result[0][1]['gluuPassportConfiguration']:
                    pp_conf_js = json.loads(pp_conf)
                    strategies.append(pp_conf_js['strategy'])
                    if not pp_conf_js['strategy'] in new_strategies:
                        if pp_conf_js['fieldset'][0].has_key('value'):
                            
                            if not '_client_' in pp_conf_js['fieldset'][0]['value']:
                                strategy={'strategy':pp_conf_js['strategy'], 'fieldset':[]}
                                for st_comp in pp_conf_js['fieldset']:
                                    strategy['fieldset'].append({'value1':st_comp['key'], 'value2':st_comp['value'], "hide":False,"description":""})        
                                new_strategies[pp_conf_js['strategy'] ] = json.dumps(strategy)
                                change = True
                        else:
                            new_strategies[pp_conf_js['strategy'] ] = pp_conf

                if change:
                    new_strategies_list = new_strategies.values()
                    self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'gluuPassportConfiguration',  new_strategies_list)])

            print "Modifying User's oxExternalUid entries ..."
            result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'(&(objectClass=gluuPerson)(oxExternalUid=*))')

            for people in result:
                dn = people[0]
                for oxExternalUid in people[1]['oxExternalUid']:
                    strategy_p = oxExternalUid.split(':')
                    new_oxExternalUid = []
                    change = False
                    if strategy_p[0] in strategies:
                        change = True
                        str_text = 'passport-{0}:{1}'.format(strategy_p[0],strategy_p[1]) 
                        new_oxExternalUid.append(str_text)
                    else:
                        new_oxExternalUid.append(oxExternalUid)

                    if change:                
                        self.conn.modify_s(dn, [(ldap.MOD_REPLACE, 'oxExternalUid',  new_oxExternalUid)])
            
        passport_default_fn = '/etc/default/passport'
        passport_default_content = open(passport_default_fn).read()

        if not 'NODE_LOGS' in passport_default_content:
            passport_default_content += '\nNODE_LOGS=$NODE_BASE/logs\n'
            print passport_default_content
            with open(passport_default_fn,'w') as w:
                w.write(passport_default_content)

        pp_conf = json.load(open('/etc/gluu/conf/passport-config.json'))
        
        pp_conf['applicationStartpoint'] = "https://{0}/oxauth/auth/passport/passportlogin.htm".format(self.setup_properties['hostname'])
        pp_conf['applicationEndpoint'] = 'https://{0}/oxauth/postlogin.htm'.format(self.setup_properties['hostname'])

        with open('/etc/gluu/conf/passport-config.json','w') as W:
            json.dump(pp_conf, W, indent=2)

        if not os.path.exists('/etc/certs/passport-sp.key'):
            os.system('/usr/bin/openssl genrsa -des3 -out /etc/certs/passport-sp.key.orig -passout pass:secret 2048')
            os.system('/usr/bin/openssl rsa -in /etc/certs/passport-sp.key.orig -passin pass:secret -out /etc/certs/passport-sp.key')
            os.system('/usr/bin/openssl req -new -key /etc/certs/passport-sp.key -out /etc/certs/passport-sp.csr -subj /C={0}/ST={1}/L={2}/O={3}/CN={4}/emailAddress={5}'.format(
                            self.setup_properties['countryCode'],
                            self.setup_properties['state'],
                            self.setup_properties['city'],
                            self.setup_properties['orgName'],
                            self.setup_properties['orgName'],
                            self.setup_properties['admin_email']
                        ))
            os.system('/usr/bin/openssl x509 -req -days 365 -in /etc/certs/passport-sp.csr -signkey /etc/certs/passport-sp.key -out /etc/certs/passport-sp.crt')
            os.system('chown root:gluu /etc/certs/passport-sp.key.orig')
            os.system('chmod 440 /etc/certs/passport-sp.key.orig')
            os.system('chown node:node /etc/certs/passport-sp.key')
            os.system('chown node:node /etc/certs/passport-sp.crt')


    def updateOtherLDAPEntries(self):
        
        result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'(|(objectClass=oxAuthUmaResourceSet)(structuralObjectClass=oxAuthUmaResourceSet))')
        
        for entry in result:
            dn = entry[0]            
            for e in entry[1]:
                if 'oxAuthUmaResourceSet' in entry[1][e]:
                    entry[1][e].remove('oxAuthUmaResourceSet')
                    entry[1][e].append('oxUmaResource')
                
            self.conn.delete_s(dn)
            self.conn.add_s(dn, modlist.addModlist(entry[1]))

        result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'(|(objectClass=oxAuthUmaResourceSetPermission)(structuralObjectClass=oxAuthUmaResourceSetPermission))')
        
        for entry in result:
            dn = entry[0]
            for e in entry[1]:
                if 'oxAuthUmaResourceSet' in entry[1][e]:
                    entry[1][e].remove('oxAuthUmaResourceSetPermission')
                    entry[1][e].append('oxUmaResourcePermission')
                
            self.conn.delete_s(dn)
            self.conn.add_s(dn, modlist.addModlist(entry[1]))

        result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'(|(oxMemcachedConfiguration=*)(oxCacheConfiguration=*))', ['oxMemcachedConfiguration','oxCacheConfiguration'])

        for entry in result:
            dn = entry[0]
            for e in entry[1]:
                entry[1][e] = 'oxCacheConfiguration: {"cacheProviderType":"IN_MEMORY","memcachedConfiguration":{"servers":"localhost:11211","maxOperationQueueLength":100000,"bufferSize":32768,"defaultPutExpiration":60,"connectionFactoryType":"DEFAULT"},"inMemoryConfiguration":{"defaultPutExpiration":60},"redisConfiguration":{"redisProviderType":"STANDALONE","servers":"localhost:6379","defaultPutExpiration":60}, nativePersistenceConfiguration: {"defaultPutExpiration":60}}'

            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, e,  entry[1][e])])

    def createOpenTrustStore(self):
        if self.ldap_type == 'openldap':

            if not os.path.exists('/etc/certs/openldap.pkcs12'):
                print "Creating truststore for openldap certificate"
                random_pw = str(uuid.uuid4()).split('-')[-1]
                print "Password for trustore", random_pw
                cmd_l = ['/usr/bin/openssl',
                  'pkcs12',
                  '-export',
                  '-inkey',
                  '/etc/certs/openldap.key',
                  '-in',
                  '/etc/certs/openldap.crt',
                  '-out',
                  '/etc/certs/openldap.pkcs12',
                  '-name',
                  self.setup_properties['hostname'],
                  '-passout',
                  'pass:'+random_pw
                  ]

                cmd = " ".join(cmd_l)
                os.system(cmd)

                cmd_l= ['/opt/jre/bin/keytool',
                  '-importkeystore',
                  '-srckeystore',
                  '/etc/certs/openldap.pkcs12',
                  '-srcstorepass',
                  random_pw,
                  '-srcstoretype',
                  'PKCS12',
                  '-destkeystore',
                  '/etc/certs/openldap.jks',
                  '-deststorepass',
                  random_pw,
                  '-deststoretype',
                  'JKS',
                  '-keyalg',
                  'RSA',
                  '-noprompt'
                  ]

                cmd = " ".join(cmd_l)
                os.system(cmd)

                encoded_pw = os.popen('/opt/gluu/bin/encode.py ' + random_pw).read().strip()
               
                ox_ldap_properties = (
                    '\nssl.trustStoreFile: /etc/certs/openldap.pkcs12\n'
                    'ssl.trustStorePin: {0}\n'
                    'ssl.trustStoreFormat: pkcs12\n\n'
                    'certificateAttributes=userCertificate\n').format(encoded_pw)

                ox_ldap_properties_fn = '/etc/gluu/conf/ox-ldap.properties'
                with open(ox_ldap_properties_fn,'a') as f:
                    f.write(ox_ldap_properties)

                os.system('chown root:gluu -R /etc/certs/openldap.jks')
                os.system('chown root:gluu -R /etc/certs/openldap.pkcs12')
                os.system('chmod  u=r,g=r,o=- /etc/certs/openldap.jks')
                os.system('chmod  u=r,g=r,o=- /etc/certs/openldap.pkcs12')


    def updateDefaultDettings(self):
        if self.cur_version >= '3.1.3':
            return

        change_default=(
                        ('/etc/default/idp', ['-XX:+DisableExplicitGC', '-XX:+UseG1GC', '-Dgluu.base=/etc/gluu', '-Dserver.base=/opt/gluu/jetty/idp']),
                        )

        for file_n, ext in change_default:
            if os.path.exists(file_n):
                tmp = open(file_n).readlines()
                
                for i in range(len(tmp)):
                    line = tmp[i].strip()
                    
                    if line.startswith('JAVA_OPTIONS'):
                        n = line.find('=')
                        JAVA_OPTIONS = line[n+1:].strip().strip('"')
                        cur_options = ['-server']
                        
                        for opt in JAVA_OPTIONS.split():
                            if opt.startswith('-Xms') or opt.startswith('-Xmx') or opt.startswith('-XX:MaxMetaspaceSize'):
                                cur_options.append(opt)

                        cur_options += ext
                        new_line = 'JAVA_OPTIONS="{0}"\n'.format(' '.join(cur_options))
                        tmp[i] = new_line
                        
                with open(file_n,'w') as f:
                    f.write(''.join(tmp))


    def updateStartIni(self):
        if self.cur_version >= '3.1.3':
            return
        
        for service in ('oxauth', 'identity','idp'):
            if os.path.exists(os.path.join(self.gluu_app_dir, service, 'start.ini')):
                os.system('cp {0} {1}'.format(
                          os.path.join(self.update_temp_dir, service+'_start.ini'),
                         os.path.join(self.gluu_app_dir, service, 'start.ini'),
                         )
                    )

        os.system('/opt/jre/bin/java -jar /opt/jetty/start.jar jetty.home=/opt/jetty jetty.base=/opt/gluu/jetty/oxauth --add-to-start=http-forwarded')
        os.system('/opt/jre/bin/java -jar /opt/jetty/start.jar jetty.home=/opt/jetty jetty.base=/opt/gluu/jetty/identity --add-to-start=http-forwarded')



    def updateOtherLDAP(self):
        
        if self.cur_version < '3.1.3':
            result = self.conn.search_s('ou=appliances,o=gluu',ldap.SCOPE_SUBTREE, '(oxTrustConfAttributeResolver=*)', ['oxTrustConfAttributeResolver'])
            if result:
                dn = result[0][0]
                try:
                    oldConfig = json.loads(result[0][1]['oxTrustConfAttributeResolver'][0])
                    newConfig = json.dumps(
                            {'nameIdConfigs':[ {

                                    'name':oldConfig['attributeName'],
                                    'sourceAttribute': oldConfig.get('attributeBase', oldConfig.get('base')),
                                    'nameIdType': oldConfig['nameIdType'],
                                    'enabled': oldConfig['enabled'],
                            }]})

                    self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxTrustConfAttributeResolver',  newConfig)])
                except:
                    pass

        result = self.conn.search_s('ou=appliances,o=gluu',ldap.SCOPE_SUBTREE,'(oxCacheConfiguration=*)', ['oxCacheConfiguration','oxAuthenticationMode', 'oxTrustAuthenticationMode'])
        dn = result[0][0]

        if not 'oxAuthenticationMode' in result[0][1]:
            self.conn.modify_s(dn, [( ldap.MOD_ADD, 'oxAuthenticationMode',  ['auth_ldap_server'])])
            print 'oxAuthenticationMode added'
        else:
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxAuthenticationMode',  ['auth_ldap_server'])])
            print 'oxAuthenticationMode was set to auth_ldap_server'

        if not 'oxTrustAuthenticationMode' in result[0][1]:
            self.conn.modify_s(dn, [( ldap.MOD_ADD, 'oxTrustAuthenticationMode',  ['auth_ldap_server'])])
            print 'oxTrustAuthenticationMode added'
        else:
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxTrustAuthenticationMode',  ['auth_ldap_server'])])
            print 'oxTrustAuthenticationMode was set to auth_ldap_server'
        
        oxCacheConfiguration = '{"cacheProviderType": "IN_MEMORY", "memcachedConfiguration": {"servers":"localhost:11211", "maxOperationQueueLength":100000, "bufferSize":32768, "defaultPutExpiration":60, "connectionFactoryType": "DEFAULT"}, "inMemoryConfiguration": {"defaultPutExpiration":60}, "redisConfiguration":{"servers":"localhost:6379", "defaultPutExpiration": 60}}'
        self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxCacheConfiguration',  oxCacheConfiguration)])


        changes = { 'oxAuthConfDynamic': [

                        ("baseEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1".format(self.hostname)),
                        ("authorizationEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/authorize".format(self.hostname)),
                        ("tokenEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/token".format(self.hostname)),
                        ("userInfoEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/userinfo".format(self.hostname)),
                        ("clientInfoEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/clientinfo".format(self.hostname)),
                        ("checkSessionIFrame", 'change', 'entry', "https://{0}/oxauth/opiframe".format(self.hostname)),
                        ("endSessionEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/end_session".format(self.hostname)),
                        ("jwksUri", 'change', 'entry', "https://{0}/oxauth/restv1/jwks".format(self.hostname)),
                        ("registrationEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/register".format(self.hostname)),
                        ("openIdDiscoveryEndpoint", 'change', 'entry', "https://{0}/.well-known/webfinger".format(self.hostname)),
                        ("openIdConfigurationEndpoint", 'change', 'entry', "https://{0}/.well-known/openid-configuration".format(self.hostname)),
                        ("idGenerationEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/id".format(self.hostname)),
                        ("introspectionEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/introspection".format(self.hostname)),
                        ("umaConfigurationEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/uma2-configuration".format(self.hostname)),
                        ("loginPage", 'change', 'entry', "https://{0}/oxauth/login.htm".format(self.hostname)),
                        ("authorizationPage", 'change', 'entry', "https://{0}/oxauth/authorize.htm".format(self.hostname)),
                        ("checkSessionIFrame", 'change', 'entry', "https://{0}/oxauth/opiframe.htm".format(self.hostname)),
                        
                        ('responseTypesSupported', 'change', 'entry',[
                                    ["code"],
                                    ["code", "id_token"],
                                    ["token"],
                                    ["token", "id_token"],
                                    ["code", "token"],
                                    ["code", "token", "id_token"],
                                    ["id_token"]
                                ]),
                                

                        ('grantTypesSupported', 'add', 'element', 'urn:ietf:params:oauth:grant-type:uma-ticket'),
                        ('idTokenSigningAlgValuesSupported', 'add', 'element', "none"),
                        ('idTokenTokenBindingCnfValuesSupported', 'add', 'entry', ["tbh"]),
                        ('dynamicGrantTypeDefault', 'add', 'entry',[
                                "authorization_code",
                                "implicit",
                                "client_credentials",
                                "refresh_token",
                                "urn:ietf:params:oauth:grant-type:uma-ticket"
                            ]),

                        ('umaValidateClaimToken', 'add', 'entry', False),

                        ('umaGrantAccessIfNoPolicies', 'add', 'entry', False),
                        ('skipAuthorizationForOpenIdScopeAndPairwiseId', 'add', 'entry', False),
                        ('personCustomObjectClassList', 'add', 'entry', ["gluuCustomPerson", "gluuPerson" ]),
                                
                        ('persistIdTokenInLdap', 'add', 'entry', False),
                        ('persistRefreshTokenInLdap', 'add', 'entry', True),
                        ('sessionIdLifetime', 'add', 'entry', 86400),
                        ('enableClientGrantTypeUpdate', 'add', 'entry', True),
                        ('corsConfigurationFilters', 'add', 'entry', [
                                {
                                    "filterName": "CorsFilter",
                                    "corsAllowedOrigins": "*",
                                    "corsAllowedMethods": "GET,POST,HEAD,OPTIONS",
                                    "corsAllowedHeaders": "Origin,Authorization,Accept,X-Requested-With,Content-Type,Access-Control-Request-Method,Access-Control-Request-Headers",
                                    "corsExposedHeaders": "",
                                    "corsSupportCredentials": True,
                                    "corsLoggingEnabled": False,
                                    "corsPreflightMaxAge": 1800,
                                    "corsRequestDecorate": True
                                }
                            ]),

                        ('logClientIdOnClientAuthentication', 'add', 'entry', True),
                        ('logClientNameOnClientAuthentication', 'add', 'entry', False),
                        ('httpLoggingEnabled', 'add', 'entry', False),
                        ('httpLoggingExludePaths', 'add', 'entry',[]),
                        ('externalLoggerConfiguration', 'add', 'entry',''),
                        ('authorizationRequestCustomAllowedParameters', 'add', 'entry',["customParam1","customParam2","customParam3"]),
                            
                        ('legacyDynamicRegistrationScopeParam', 'add', 'entry', False),
                        ('useCacheForAllImplicitFlowObjects', 'add', 'entry', False),
                        ('disableU2fEndpoint', 'add', 'entry', False),


                        ('grantTypesSupported','remove', 'element', 'urn:ietf:params:oauth:grant-type:jwt-bearer'),
                        ('grantTypesSupported','add', 'element', 'password'),
                        ('grantTypesSupported','add', 'element', 'client_credentials'),
                        ('grantTypesSupported','add', 'element', 'refresh_token'),

                        ('umaRptLifetime', 'add', 'entry',  3600),
                        ('accessTokenLifetime', 'add', 'entry', 300), 
                        
                        ('dynamicRegistrationCustomAttributes', 'remove', 'entry', ["myCustomAttr1", "myCustomAttr2"]),
                        ('sessionStateHttpOnly', 'remove', 'entry', False),
                        ('shortLivedAccessTokenLifetime','remove', 'entry', 300),
                        ('idTokenTokenBindingCnfValuesSupported', 'add', 'entry', ["tbh"]),
                        
                        ('introspectionAccessTokenMustHaveUmaProtectionScope', 'add', 'entry', False),
                        ('umaRptLifetime', 'add', 'entry', 3600),
                        ('umaTicketLifetime', 'add', 'entry', 3600),
                        ('umaPctLifetime', 'add', 'entry', 2592000),
                        
                        ('umaGrantAccessIfNoPolicies', 'change', 'entry', False),
                        ('umaRestrictResourceToAssociatedClient', 'add', 'entry', False),
                        ('disableU2fEndpoint', 'add', 'entry', False),
                        ('authenticationProtectionConfiguration', 'add', 'entry', {"attemptExpiration": 15, "maximumAllowedAttempts": 10, "maximumAllowedAttemptsWithoutDelay": 4, "delayTime": 2, "bruteForceProtectionEnabled": False } ),
                        ('openidScopeBackwardCompatibility', 'add',  'entry', True),
                    ],
    
            'oxTrustConfApplication' : [

                    ("baseEndpoint", 'change', 'entry', "https://{0}/identity/restv1".format(self.hostname)),
                    ("loginRedirectUrl", 'change', 'entry', "https://{0}/identity/authentication/getauthcode".format(self.hostname)),
                    ("scimUmaResourceId", 'change', 'entry', "0f13ae5a-135e-4b01-a290-7bbe62e7d40f"),
                    ("scimUmaScope", 'change', 'entry', "https://{0}/oxauth/restv1/uma/scopes/scim_access".format(self.hostname)),
                    ("passportUmaResourceId", 'change', 'entry', "0f963ecc-93f0-49c1-beae-ad2006abbb99"),
                    ("passportUmaScope", 'change', 'entry', "https://{0}/oxauth/restv1/uma/scopes/passport_access".format(self.hostname)),
                    ('scimTestModeAccessToken','remove', 'entry', None),
                    ('ScimProperties','remove', 'entry', None),
                    ('ScimProperties','add', 'entry', {'maxCount': 200}),
                    ('passwordResetRequestExpirationTime', 'add', 'entry', 600),

                ],
        }


        for config_element in changes:
            print "Updating", config_element
            ldap_filter = '({0}=*)'.format(config_element)
            result = self.conn.search_s('ou=appliances,o=gluu',ldap.SCOPE_SUBTREE, ldap_filter, [config_element])
            
            dn = result[0][0]
            
            js_conf = json.loads(result[0][1][config_element][0])

            for key, change_type, how_change, value in changes[config_element]:

                if change_type == 'add':
                    if how_change == 'entry':
                        js_conf[key] = value
                    elif how_change == 'element':
                        if not value in js_conf[key]:
                            js_conf[key].append(value)
                elif change_type == 'change':
                    if how_change == 'entry':
                        js_conf[key] = value
                elif change_type == 'remove':
                    if how_change == 'entry':
                        if key in js_conf:
                            del js_conf[key]
                    elif how_change == 'element':
                        if value in js_conf[key]:
                            js_conf[key].remove(value)

            new_conf = json.dumps(js_conf,indent=4)
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, config_element,  new_conf)])


        dn = 'inum=%(oxauth_client_id)s,ou=clients,o=%(inumOrg)s,o=gluu' % self.setup_properties


        mod_dict = {'oxAuthGrantType': ['authorization_code', 'implicit', 'refresh_token'],
                    'oxClaimRedirectURI': ['https://{0}/oxauth/restv1/uma/gather_claims'.format(self.setup_properties['hostname'])],
                    'oxAuthPostLogoutRedirectURI': ['https://{0}/identity/authentication/finishlogout'.format(self.hostname),
                                    ],

                    }

        rep_dict = { 'oxAuthRedirectURI': [
                                        'https://{0}/identity/scim/auth'.format(self.hostname),
                                        'https://{0}/identity/authentication/authcode'.format(self.hostname),
                                        'https://{0}/identity/authentication/getauthcode'.format(self.hostname),
                                        'https://{0}/cas/login'.format(self.hostname),
                                        'https://{0}/oxauth/restv1/uma/gather_claims?authentication=true'.format(self.hostname),
                                        'https://{0}/oxauth/restv1/uma/gather_claims'.format(self.hostname),
                                        ],
                    }

        result = self.conn.search_s(dn, ldap.SCOPE_BASE,'(objectClass=*)', mod_dict.keys())

        for entry in mod_dict:
            add_list = []
            if entry in result[0][1]:
                for e in mod_dict[entry]:
                    if not e in result[0][1][entry]:
                        add_list.append(e)
            else:
                add_list = mod_dict[entry][:]

            if add_list:
                self.conn.modify_s(dn, [( ldap.MOD_ADD, entry,  add_list)])
        
        for entry in rep_dict:
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, entry,  rep_dict[entry])])

    def update_shib(self):
        #saml-nameid.xml.vm is missing after upgrade

        if not os.path.exists(self.saml_meta_data):
            return


        print "Backing up /opt/shibboleth-idp to", self.backup_folder
        os.system('cp -r /opt/shibboleth-idp '+self.backup_folder)
        print "Updating idp-metadata.xml"
        self.setup_properties['idp3SigningCertificateText'] = open('/etc/certs/idp-signing.crt').read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')
        self.setup_properties['idp3EncryptionCertificateText'] = open('/etc/certs/idp-encryption.crt').read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')

        shutil.copy(self.saml_meta_data, self.backup_folder)

        temp_fn = os.path.join(self.update_temp_dir, 'idp3/metadata/idp-metadata.xml')

        with open(temp_fn) as f:
            temp = f.read()

        new_saml_meta_data = fomatWithDict(temp, self.setup_properties)

        with open(self.saml_meta_data,'w') as f:
            f.write(new_saml_meta_data)


        changes = (('/opt/shibboleth-idp/conf/ldap.properties', [('idp.attribute.resolver.LDAP.searchFilter', '(|(uid=$requestContext.principalName)(mail=$requestContext.principalName))'),
                                                                ]),
                    ('/opt/shibboleth-idp/conf/idp.properties', [
                                                                ('idp.authn.flows', 'oxAuth'),
                                                                ]),
                    )
        
        for prop_file, change_list in changes:
        
            if os.path.exists(prop_file):
                f=open(prop_file).readlines()
                for i in range(len(f)):
                    l = f[i]
                    ls = l.split('=')
                    if ls:
                        for change in change_list:
                            if ls[0].strip() == change[0]:
                                f[i] = ' = '.join(change) + '\n'
                with open(prop_file,'w') as w:
                    w.write(''.join(f))


        print "Updadting shibboleth-idp"
        os.chdir('/opt')
        os.system('/opt/jre/bin/jar xf {0}'.format(os.path.join(self.app_dir,'shibboleth-idp.jar')))
        os.system('rm -r /opt/META-INF')
        os.system('chown -R jetty:jetty /opt/shibboleth-idp')
        os.system('cp {0} /opt/gluu/jetty/identity/conf/shibboleth3/idp'.format(os.path.join(self.app_dir,'temp/metadata-providers.xml.vm')))
        os.system('cp {0} /opt/gluu/jetty/identity/conf/shibboleth3/idp'.format(os.path.join(self.app_dir,'temp/saml-nameid.xml.vm')))
        os.system('chmod u=rw,g=r,o=r /opt/gluu/jetty/identity/conf/shibboleth3/idp/metadata-providers.xml.vm')
        os.system('chmod u=rw,g=r,o=r /opt/gluu/jetty/identity/conf/shibboleth3/idp/saml-nameid.xml.vm')

    def replace_scripts(self):

        print "Backing up current scripts"
        pw_file = '/tmp/.' + str(uuid.uuid4()).split('-')[-1]
        with open(pw_file,'w') as w:
            w.write(self.ldap_bind_pw)
        cmd = "/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -D '{0}' -j {3} -b 'ou=scripts,o={1},o=gluu' 'objectClass=oxCustomScript' > {2}".format(
                          self.ldap_bind_dn, self.inumOrg, os.path.join(self.backup_folder, 'scripts.ldif'), pw_file)
        os.system(cmd)
        os.remove(pw_file)

        if not os.path.exists(self.extensionFolder):
            return None

        for extensionType in os.listdir(self.extensionFolder):
            extensionTypeFolder = os.path.join(self.extensionFolder, extensionType)
            if not os.path.isdir(extensionTypeFolder):
                continue

            for scriptFile in os.listdir(extensionTypeFolder):
                scriptFilePath = os.path.join(extensionTypeFolder, scriptFile)
                base64ScriptFile = base64.b64encode(open(scriptFilePath).read()).strip()

                # Prepare key for dictionary
                extensionScriptName = '%s_%s' % (extensionType, os.path.splitext(scriptFile)[0])
                extensionScriptName = extensionScriptName.decode('utf-8').lower()

                self.setup_properties[extensionScriptName] = base64ScriptFile

        scripts_ldif_temp = open(self.scripts_ldif).read()
        scripts_ldif_temp = scripts_ldif_temp % self.setup_properties

        ldif_io = io.StringIO(scripts_ldif_temp.decode('utf-8'))
        ldif_io.seek(0)

        ldif_parser = MyLdif(ldif_io)
        ldif_parser.parse()

        script_replacements = {
                self.inumOrg + '!0011!2DAF.F995': self.inumOrg +'!0011!2DAF.F9A5'
            }

        search_dn = 'ou=scripts,o=%(inumOrg)s,o=gluu' % self.setup_properties

        result = self.conn.search_s(search_dn, ldap.SCOPE_SUBTREE, '(objectClass=oxCustomScript)')

        enabled_scripts = []
        current_scripts = []
        for e in result:
            current_scripts.append(str(e[0]))
            if 'true' in e[1]['gluuStatus']:
                inum = e[1]['inum'][0]
                enabled_scripts.append(script_replacements.get(inum, inum))

        for e in ldif_parser.entries:
            if e[1]['inum'][0] in enabled_scripts:
                e[1]['gluuStatus'] = ['true']

        for dn, entry in ldif_parser.entries:
            ldif = modlist.addModlist(entry)
            if dn in current_scripts:
                print "Deleting current script", dn
                self.conn.delete_s(dn)
            print "Adding new script", dn
            self.conn.add_s(dn, ldif)

    def updateApacheConfig(self):
        
        apache2_conf_fn = os.path.join(self.update_temp_dir, 'httpd.conf')
        apache2_ssl_conf_fn = os.path.join(self.update_temp_dir, 'https_gluu.conf')
        apache2_24_conf_fn = os.path.join(self.update_temp_dir,'httpd_2.4.conf')
        
        apache2_conf = fomatWithDict(open(apache2_conf_fn).read(), self.setup_properties)
        
        apache2_ssl_conf = fomatWithDict(open(apache2_ssl_conf_fn).read(), self.setup_properties)
        apache2_24_conf = fomatWithDict(open(apache2_24_conf_fn).read(), self.setup_properties)

        if (self.os_type in ['centos', 'red'] and self.os_version >= '7') or self.os_type=='fedora':
            shutil.copy('/etc/httpd/conf/httpd.conf', self.backup_folder)
            with open('/etc/httpd/conf/httpd.conf','w') as w:
                w.write(apache2_24_conf)
            
            shutil.copy('/etc/httpd/conf.d/https_gluu.conf', self.backup_folder)
            with open('/etc/httpd/conf.d/https_gluu.conf','w') as w:
                w.write(apache2_ssl_conf)
        
        if (self.os_type in ['centos', 'red'] and self.os_version < '7'):
            shutil.copy('/etc/httpd/conf/httpd.conf', self.backup_folder)
            with open('/etc/httpd/conf/httpd.conf','w') as w:
                w.write(apache2_conf)

            shutil.copy('/etc/httpd/conf.d/https_gluu.conf', self.backup_folder)
            with open('/etc/httpd/conf.d/https_gluu.conf','w') as w:
                w.write(apache2_ssl_conf)

        if self.os_type in ['debian', 'ubuntu']:
            shutil.copy('/etc/apache2/sites-available/https_gluu.conf', self.backup_folder)
            with open('/etc/apache2/sites-available/https_gluu.conf','w') as w:
                w.write(apache2_ssl_conf)

    def createIDPClient(self):
        
        clientTwoQuads = '%s.%s' % (getQuad(),getQuad())

        idp_client_id = '%s!0008!%s' % (self.setup_properties['inumOrg'], clientTwoQuads)
        self.setup_properties['idp_client_id'] = idp_client_id

        dn = "inum=%(idp_client_id)s,ou=clients,o=%(inumOrg)s,o=gluu" % self.setup_properties
        
        idpClient_pw = getPW()
        idpClient_encoded_pw = obscure(idpClient_pw, self.setup_properties['encode_salt'])


        with open('/install/community-edition-setup/setup.properties.last','a') as W:
            W.write('idp_client_id=' + idp_client_id+'\n')
            W.write('idpClient_pw=' + idpClient_pw+'\n')
            W.write('idpClient_encoded_pw=' + idpClient_encoded_pw+'\n')


        attrs = { 'objectClass': ['oxAuthClient', 'top'],
                  'displayName': ['IDP client'],
                  'inum': [idp_client_id],
                  'oxAuthClientSecret': [idpClient_encoded_pw],
                  'oxAuthAppType': ['web'],
                  'oxAuthResponseType': ['code'],
                  'oxAuthGrantType': ['authorization_code','refresh_token'],
                  'oxAuthScope': [ 'inum=%(inumOrg)s!0009!F0C4,ou=scopes,o=%(inumOrg)s,o=gluu' % self.setup_properties,
                                   'inum=%(inumOrg)s!0009!10B2,ou=scopes,o=%(inumOrg)s,o=gluu' % self.setup_properties,
                                   'inum=%(inumOrg)s!0009!764C,ou=scopes,o=%(inumOrg)s,o=gluu' % self.setup_properties,
                                ],
                  'oxAuthRedirectURI': ['https://%(hostname)s/idp/Authn/oxAuth' % self.setup_properties],
                  'oxAuthPostLogoutRedirectURI': ['https://%(hostname)s/idp/profile/Logout' % self.setup_properties],
                  'oxAuthPostLogoutRedirectURI': ['https://%(hostname)s/identity/authentication/finishlogout' % self.setup_properties],
                  'oxAuthTokenEndpointAuthMethod': ['client_secret_basic'],
                  'oxAuthIdTokenSignedResponseAlg': ['HS256'],
                  'oxAuthTrustedClient': ['true'],
                  'oxAuthSubjectType': ['public'],
                  'oxPersistClientAuthorizations': ['false'],
                  'oxAuthLogoutSessionRequired': ['true'],
                  }

        ldif = modlist.addModlist(attrs)
        self.conn.add_s(dn,ldif)


        #Fix oxIDP for SAML
        dn = 'ou=oxidp,ou=configuration,inum=%(inumAppliance)s,ou=appliances,o=gluu' % self.setup_properties        
        result = self.conn.search_s(dn, ldap.SCOPE_BASE,'(objectClass=*)')
        oxConfApplication = json.loads(result[0][1]['oxConfApplication'][0])
        oxConfApplication['openIdClientId'] = idp_client_id
        oxConfApplication['openIdClientPassword'] = idpClient_encoded_pw
        
        oxConfApplication['openIdRedirectUrl'] = 'https://{0}/idp/Authn/oxAuth'.format(self.hostname)
        oxConfApplication['openIdPostLogoutRedirectUri'] = 'https://{0}/idp/profile/Logout'.format(self.hostname)
        oxConfApplication_js = json.dumps(oxConfApplication)
        self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxConfApplication',  oxConfApplication_js)])        


updaterObj = GluuUpdater()
updaterObj.updateApacheConfig()
updaterObj.updateLdapSchema()
updaterObj.ldappConn()
updaterObj.createIDPClient()

if repace_scripts:
    updaterObj.replace_scripts()

updaterObj.updateWar()
updaterObj.addUserCertificateMetadata()
updaterObj.fixAttributeTypes()
updaterObj.addOxAuthClaimName()
updaterObj.modifySectorIdentifiers()
updaterObj.checkIdpMetadata()
updaterObj.upgradeJetty()
updaterObj.updatePassport()
updaterObj.createOpenTrustStore()
updaterObj.updateDefaultDettings()
updaterObj.updateStartIni()
updaterObj.updateOtherLDAP()
updaterObj.update_shib()


# TODO: is this necassary?
#updaterObj.updateOtherLDAPEntries()

#./makeself.sh --target /opt/upd/3.1.4upg/  /opt/upd/3.1.4upg/ 3-1-4-upg.sh  "Gluu Updater Package 3.1.4.upg" /opt/upd/3.1.4upg/bin/update.py

print """
\033[;1mPlease Note:\033[0;0m oxAuthenticationMode and oxTrustAuthenticationMode was
set to auth_ldap_server in case custom authentication script fails.
Please review your scripts and adjust default authentication method

Update is complete, please exit from container and restart gluu server
"""
