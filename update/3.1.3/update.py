import os
import time
import glob
import re
import shutil
import json
import base64
from pyDes import *

import ldap
import ldap.modlist as modlist
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

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
    
def get_ldap_admin_password():    
    salt_file = open('/etc/gluu/conf/salt').read()
    salt = salt_file.split('=')[1].strip()
    ox_ldap_properties_file = '/etc/gluu/conf/ox-ldap.properties'
    for l in open(ox_ldap_properties_file):
        if l.startswith('bindPassword'):
            s = l.split(':')[1].strip()
            engine = triple_des(salt, ECB, pad=None, padmode=PAD_PKCS5)
            cipher = triple_des(salt)
            decrypted = cipher.decrypt(base64.b64decode(s), padmode=PAD_PKCS5)
            return decrypted

class GluuUpdater:
    def __init__(self):
        self.update_version = '3.1.3.sp1'
        self.update_dir = '/opt/upd/' + self.update_version
        self.setup_properties = parse_setup_properties()
        self.ldap_type = self.setup_properties['ldap_type']
        self.ldap_host = self.setup_properties['hostname'] 
        
        if self.ldap_type == 'opendj':
            self.ldap_bind_dn = self.setup_properties['opendj_ldap_binddn']
        elif self.ldap_type == 'openldap':
            self.ldap_bind_dn = self.setup_properties['ldap_binddn']
            
        self.ldap_bind_pw = get_ldap_admin_password()
        self.inumOrg = self.setup_properties['inumOrg']
        self.hostname = self.setup_properties['hostname'] 
        self.backup_time = time.strftime('%Y-%m-%d.%H:%M:%S')
        self.backup_folder = '/opt/upd/{0}/backup_openldap_{1}'.format(self.update_version, self.backup_time)
        
        if not os.path.exists(self.backup_folder):
            os.mkdir(self.backup_folder)

    def ldappConn(self):
        self.conn = ldap.initialize('ldaps://{0}:1636'.format(self.ldap_host))
        self.conn.simple_bind_s(self.ldap_bind_dn, self.ldap_bind_pw)
        


    def updateOxAuthConf(self):

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

        if json_update:
            jsons = json.dumps(oxAuthConfDynamic)
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxAuthConfDynamic',  jsons)])
            print 'oxAuthConfDynamic updated'
        else:
            print 'No need to update oxAuthConfDynamic'


    def addUserCertificateMetadata(self):
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
        dn = 'inum={0}!0005!D2E0,ou=attributes,o={0},o=gluu'.format(self.inumOrg)
        result = self.conn.search_s(dn,  ldap.SCOPE_BASE, attrlist=['oxAuthClaimName'])
        if not result[0][1]:
            self.conn.modify_s(dn, [( ldap.MOD_ADD, 'oxAuthClaimName',  ['member_of'])]) 
            print dn, 'modified'

        print dn, "not modified"
        
    def modifySectorIdentifiers(self):
        sector_identifiers = 'ou=sector_identifiers,o={0},o=gluu'.format(self.inumOrg)        
        result = self.conn.search_s(sector_identifiers, ldap.SCOPE_SUBTREE)
        for dn, entry in result:
            if  dn.startswith('inum='):
                dn_s = ldap.dn.str2dn(dn)
                newrdn = 'oxId={0}'.format(dn_s[0][0][1])
                self.conn.rename_s(dn, newrdn)

    def copyFiles(self):
        for f in ('/opt/gluu/jetty/oxauth/custom/i18n', '/opt/gluu/jetty/identity/custom/i18n'):
            os.system('mkdir -p {0}'.format(f))
            os.system('chown jetty:jetty {0}'.format(f))

        if os.path.exists('/install/community-edition-setup/output/jetty/oxauth_web_resources.xml'):
            os.system('cp /install/community-edition-setup/output/jetty/oxauth_web_resources.xml /opt/gluu/jetty/oxauth/webapps')
        if os.path.exists('/install/community-edition-setup/output/jetty/identity_web_resources.xml'):
            os.system('cp /install/community-edition-setup/output/jetty/identity_web_resources.xml  /opt/gluu/jetty/identity/webapps')
        

    def checkIdpMetadata(self):
        print "checking /opt/shibboleth-idp/metadata/idp-metadata.xml"
        idp_meatdata_file = '/opt/shibboleth-idp/metadata/idp-metadata.xml'
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
        jetty_re = re.compile('jetty-distribution-(\d+).(\d+).(\d+).(.+)')

        cur_ver = glob.glob("/opt/jetty-9.*/jetty-distribution*")[0]

        rss = jetty_re.search(os.path.basename(cur_ver)).groups()
        cur_folder = '/opt/jetty-{0}.{1}'.format(rss[0], rss[1])

        new_ver = max(glob.glob(os.path.join(self.update_dir, 'app/jetty-distribution*')))

        rss = jetty_re.search(os.path.basename(new_ver)).groups()
        new_folder = '/opt/jetty-{0}.{1}'.format(rss[0], rss[1])

        if not os.path.exists(new_folder):
            os.mkdir(new_folder)

        os.system('tar -xvf {0} -C {1}'.format(new_ver, new_folder))

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

    def updateLdapSchema(self):
        print "Updating ldap schema"
        
        if self.ldap_type == 'openldap':
            ldap_schema_dir = '/opt/gluu/schema/openldap'
            new_schema=os.path.join(self.update_dir, 'ldap/openldap/gluu.schema')
            cur_schema = os.path.join(ldap_schema_dir, 'gluu.schema')
            
        elif self.ldap_type == 'opendj':
            ldap_schema_dir = '/opt/opendj/config/schema'
            new_schema = os.path.join(self.update_dir, 'ldap/opendj/101-ox.ldif')
            cur_schema = os.path.join(ldap_schema_dir, '101-ox.ldif')        
        
        if os.path.exists(cur_schema):
            shutil.move(cur_schema, self.backup_folder)
        
        shutil.copy(new_schema, ldap_schema_dir)
        os.system('chown ldap:ldap {0}'.format(cur_schema))

updaterObj = GluuUpdater()
updaterObj.ldappConn()
updaterObj.updateOxAuthConf()
updaterObj.addUserCertificateMetadata()
updaterObj.fixAttributeTypes()
updaterObj.addOxAuthClaimName()
updaterObj.modifySectorIdentifiers()
updaterObj.checkIdpMetadata()
updaterObj.upgradeJetty()
updaterObj.updateLdapSchema()
