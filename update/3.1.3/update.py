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


result = raw_input("Starting upgrade. CONTINUE? (y|N): ")
if not result.strip() or (result.strip() and result.strip().lower()[0] != 'y'):
    print "You can re-run this script to upgrade. Bye now ..."
    sys.exit()

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


class GluuUpdater:
    def __init__(self):
        self.update_version = '3.1.3.sp1'
        self.update_dir = os.path.join('/opt/upd/', self.update_version)
        self.app_dir = os.path.join(self.update_dir,'app')
        self.setup_properties = parse_setup_properties()
        self.gluu_app_dir = '/opt/gluu/jetty'
        self.update_temp_dir = os.path.join(self.app_dir,'temp')
        self.passport_mdules_archive = os.path.join(self.app_dir, 'passport-node_modules.tgz')
        self.saml_meta_data = '/opt/shibboleth-idp/metadata/idp-metadata.xml'

        self.setup_properties['shibboleth_version'] = 'v3'

        if self.setup_properties.get('ldap_type'):
            self.ldap_type = self.setup_properties['ldap_type']
        else:
            self.ldap_type = 'openldap'
    
        self.ldap_host = 'localhost'
        
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


    def fix_war_richfaces(self):
        
        check_list = [
            '/opt/tomcat/webapps/identity.war',
            '/opt/gluu/jetty/identity/webapps/identity.war',
            '/opt/tomcat/webapps/oxauth-rp.war',
            '/opt/gluu/jetty/oxauth-rp/webapps/oxauth-rp.war',
            ]

        for war_file_path in check_list:

            if os.path.exists(war_file_path):
                war_file = os.path.basename(war_file_path)
                war_path = os.path.dirname(war_file_path)

                print "Updating", war_file_path

                war_lib_dir = os.path.join(war_path, 'WEB-INF')

                if os.path.exists(war_lib_dir):
                     os.system('rm -r -f {0}'.format(war_lib_dir))


                os.system('cp -r {0} {1}'.format(os.path.join(self.app_dir, 'WEB-INF'), war_path))

                os.chdir(war_path)

                print "Deleting old richfaces from {0}".format(war_file)

                #Get a list of files inside war file
                zip_info = os.popen('unzip -qql {0}'.format(war_file)).readlines()
                for f_info in zip_info:
                    f_size, f_date, f_time, f_name = f_info.split()

                    #Check if file is richfaces lib
                    if 'richfaces' in f_name and f_name.endswith('.jar'):
                        rf = os.path.basename(f_name)
                        os.system('zip -d {0} WEB-INF/lib/{1}'.format(war_file, rf))

                print "Adding latest richfaces to {0}".format(war_file)

                os.system('zip -g {0} WEB-INF/lib/*'.format(war_file))

                os.system('rm -r -f {0}'.format(war_lib_dir))

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
                    os.mkdir(resources_dir)
                    os.system('chown jetty:jetty ' + resources_dir)
                    
                print "Updating", war_app
                shutil.copy(new_war_app_file, app_dir)


    # TODO: Do we still need this?
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
        

    # TODO: Do we still need this?
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

        #After updateting schema we need to restart ldap server
        if self.ldap_type == 'openldap':
            os.system('/etc/init.d/solserver restart')
        else:
            os.system('/etc/init.d/opendj restart')
        #wait 10 secs for ldap server to start
        time.sleep(10)

    def updatePassport(self):
        if not os.path.exists('/opt/gluu/node/passport'):
            return
            
        print "Updating Passport"
        os.system('service passport stop')
        new_ver = glob.glob(self.update_dir+'/app/passport-*')[0]
                
        backup_folder = '/opt/upd/{0}/backup_passport_{1}'.format(self.update_version,self.backup_time)
        
        if not os.path.exists(backup_folder):
            os.mkdir(backup_folder)

        backup_file = os.path.join(backup_folder, 'passport-package-v312-backup.tar.gz')
        os.system('tar -cvpzf {0} --one-file-system /opt/gluu/node/passport/'.format(backup_file))
        os.system('rm -r -f /opt/gluu/node/passport/')

        if not os.path.exists('/opt/gluu/node/passport'):
            os.mkdir('/opt/gluu/node/passport')

        os.system('rm -r -f /tmp/passport_tmp_313')
        os.mkdir('/tmp/passport_tmp_313')
        
        os.system('tar -zxf {0} --directory /tmp/passport_tmp_313'.format(new_ver))
        os.system('cp -r /tmp/passport_tmp_313/package/* /opt/gluu/node/passport')
        index_js = os.path.join(self.update_dir, 'app', 'index.js')
        os.system('cp {0} /opt/gluu/node/passport/server/routes/'.format(index_js))
        
        saml_config = os.path.join(self.update_dir, 'app', 'passport-saml-config.json')
        os.system('cp {0} /etc/gluu/conf'.format(saml_config))
        os.system('chown node:node /etc/gluu/conf/passport-saml-config.json')
        
        log_dir = '/opt/gluu/node/passport/server/logs'

        if not os.path.exists(log_dir): 
            os.mkdir(log_dir)

        if not os.path.exists('/opt/gluu/node/passport/server/utils/misc.js'):
            open('/opt/gluu/node/passport/server/utils/misc.js','w')

        print "Extracting passport node modules"
    
        os.system('tar -zxf {0} -C /'.format(self.passport_mdules_archive))

        os.system('chown -R node:node /opt/gluu/node/passport')

        result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'(description=Passport authentication module)')

        dn=result[0][0]

        oxConfigurationProperty_list = [ 
                            {"value1":"key_store_file","value2":"/etc/certs/passport-rp.jks","hide":False,"description":""},
                            {"value1":"key_store_password","value2":"secret","hide":False,"description":""}
                        ]


        for oxc in result[0][1]['oxConfigurationProperty']:
            oxcjs = json.loads(oxc)
            if oxcjs['value1'] == oxConfigurationProperty_list[0]['value1']:
                oxConfigurationProperty_list.remove(oxConfigurationProperty_list[0])
            elif oxcjs['value1'] == oxConfigurationProperty_list[1]['value1']:
                oxConfigurationProperty_list.remove(oxConfigurationProperty_list[1])

        if oxConfigurationProperty_list:
            oxConfigurationProperty=result[0][1]['oxConfigurationProperty'][:]

            for oxc in oxConfigurationProperty_list:
                oxConfigurationProperty.append(json.dumps(oxc))

            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxConfigurationProperty',  oxConfigurationProperty)])


        oxScript = open(os.path.join(self.update_dir, 'app', 'PassportExternalAuthenticator.py')).read()
        self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxScript',  oxScript)])


        result = self.conn.search_s('o=gluu',ldap.SCOPE_SUBTREE,'(displayName=uma_client_authz_rpt_policy)')
        if result:
            dn=result[0][0]
            oxScript = open(os.path.join(self.update_dir, 'app', 'UmaClientAuthzRptPolicy.py')).read()
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxScript',  oxScript)])

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
        pp_conf['applicationEndpoint'] = 'https://{0}/oxauth/postlogin'.format(self.setup_properties['hostname'])
        w = open('/etc/gluu/conf/passport-config.json','w')
        json.dump(pp_conf, w)
        w.close()

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

        os.system('rm -r -f /tmp/passport_tmp_313')

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
                entry[1][e] = 'oxCacheConfiguration: {"cacheProviderType":"IN_MEMORY","memcachedConfiguration":{"servers":"localhost:11211","maxOperationQueueLength":100000,"bufferSize":32768,"defaultPutExpiration":60,"connectionFactoryType":"DEFAULT"},"inMemoryConfiguration":{"defaultPutExpiration":60},"redisConfiguration":{"redisProviderType":"STANDALONE","servers":"localhost:6379","defaultPutExpiration":60}}'

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
        change_default=(
                ('/etc/default/oxauth', 'JAVA_OPTIONS', 'JAVA_OPTIONS="-server -Xms256m -Xmx920m -XX:MaxMetaspaceSize=395m -XX:+DisableExplicitGC -Dgluu.base=/etc/gluu -Dserver.base=/opt/gluu/jetty/oxauth -Dlog.base=/opt/gluu/jetty/oxauth -Dpython.home=/opt/jython"'),
                ('/etc/default/identity', 'JAVA_OPTIONS', 'JAVA_OPTIONS="-server -Xms256m -Xmx613m -XX:MaxMetaspaceSize=263m -XX:+DisableExplicitGC -Dgluu.base=/etc/gluu -Dserver.base=/opt/gluu/jetty/identity -Dlog.base=/opt/gluu/jetty/identity -Dpython.home=/opt/jython -Dorg.eclipse.jetty.server.Request.maxFormContentSize=50000000"'),
                ('/etc/default/idp', 'JAVA_OPTIONS', 'JAVA_OPTIONS="-server -Xms179m -Xmx179m -XX:MaxMetaspaceSize=77m -XX:+DisableExplicitGC -XX:+UseG1GC -Dgluu.base=/etc/gluu -Dserver.base=/opt/gluu/jetty/idp"'),
           
           )

        for opt in change_default:
            if os.path.exists(opt[0]):
                tmp = open(opt[0]).readlines()
                for i in range(len(tmp)):
                    if tmp[i].startswith(opt[1]):
                        tmp[i] = opt[2]+'\n'
                with open(opt[0],'w') as f:
                    f.write(''.join(tmp))

    def updateStartIni(self):
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
        
        result = self.conn.search_s('ou=appliances,o=gluu',ldap.SCOPE_SUBTREE,'(oxCacheConfiguration=*)', ['oxCacheConfiguration','oxAuthenticationMode', 'oxTrustAuthenticationMode'])
        dn = result[0][0]

        if not 'oxAuthenticationMode' in result[0][1]:
            self.conn.modify_s(dn, [( ldap.MOD_ADD, 'oxAuthenticationMode',  ['auth_ldap_server'])])
            print 'oxAuthenticationMode added'

        if not 'oxTrustAuthenticationMode' in result[0][1]:
            self.conn.modify_s(dn, [( ldap.MOD_ADD, 'oxTrustAuthenticationMode',  ['auth_ldap_server'])])
            print 'oxTrustAuthenticationMode added'
        
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
                        

                    ],
    
            'oxTrustConfApplication' : [

                    ("baseEndpoint", 'change', 'entry', "https://{0}/identity/restv1".format(self.hostname)),
                    ("loginRedirectUrl", 'change', 'entry', "https://{0}/identity/authentication/getauthcode".format(self.hostname)),
                    ("scimUmaResourceId", 'change', 'entry', "0f13ae5a-135e-4b01-a290-7bbe62e7d40f"),
                    ("scimUmaScope", 'change', 'entry', "https://{0}/oxauth/restv1/uma/scopes/scim_access".format(self.hostname)),
                    ("passportUmaResourceId", 'change', 'entry', "0f963ecc-93f0-49c1-beae-ad2006abbb99"),
                    ("passportUmaScope", 'change', 'entry', "https://{0}/oxauth/restv1/uma/scopes/passport_access".format(self.hostname)),
                    ('scimTestModeAccessToken','remove', 'entry', None),
                    ('ScimProperties','add', 'entry', {'maxCount': 200})

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
                    'oxAuthRedirectURI': ['https://{0}/identity/authentication/getauthcode'.format(self.setup_properties['hostname']), 'https://{0}/oxauth/restv1/uma/gather_claims?authentication=true'.format(self.setup_properties['hostname'])],
                    'oxClaimRedirectURI': ['https://{0}/oxauth/restv1/uma/gather_claims'.format(self.setup_properties['hostname'])],
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


    def update_shib(self):

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


        prop_file = '/opt/shibboleth-idp/conf/ldap.properties'
        if os.path.exists(prop_file):
            f=open(prop_file).readlines()
            for i in range(len(f)):
                l = f[i]
                ls = l.split('=')
                if ls and ls[0].strip() == 'idp.attribute.resolver.LDAP.searchFilter':
                    f[i] = 'idp.attribute.resolver.LDAP.searchFilter        = (|(uid=$requestContext.principalName)(mail=$requestContext.principalName))\n'
            with open(prop_file,'w') as w:
                w.write(''.join(f))

        print "Updadting shibboleth-idp"
        os.chdir('/opt')
        os.system('/opt/jre/bin/jar xf {0}'.format(os.path.join(self.app_dir,'shibboleth-idp.jar')))
        os.system('rm -r /opt/META-INF')
        os.system('chown -R jetty:jetty /opt/shibboleth-idp')
        os.system('cp {} /opt/gluu/jetty/identity/conf/shibboleth3/idp'.format(os.path.join(self.app_dir,'temp/metadata-providers.xml.vm')))

updaterObj = GluuUpdater()
updaterObj.updateLdapSchema()
updaterObj.ldappConn()
updaterObj.fix_war_richfaces()
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

#./makeself.sh --target /opt/upd/3.1.3.sp1/  /opt/upd/3.1.3.sp1/ 3-1-3-sp1.sh  "Gluu Updater Package 3.1.3.sp1" /opt/upd/3.1.3.sp1/bin/update.py

print "Update is complete, please exit from container and restart gluu server"
