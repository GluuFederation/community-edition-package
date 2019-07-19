#!/usr/bin/python

import os
import json
import base64
import io
import re
import uuid
import time
import shutil
import argparse
import shelve
import sys
import glob

cur_dir = os.path.dirname(os.path.realpath(__file__))

package_type = None

if os.path.exists('/etc/yum.repos.d/'):
    package_type = 'rpm'
elif os.path.exists('/etc/apt/sources.list'):
    package_type = 'deb'
        

missing_packages = []

try:
    import ldap
except:
    missing_packages.append('python-ldap')


try:
    import jsonschema
except:
    missing_packages.append('python-jsonschema')


if missing_packages:
    packages_str = ' '.join(missing_packages)
    result = raw_input("Missing package(s): {0}. Install now? (Y|n): ".format(packages_str))
    if result.strip() and result.strip().lower()[0] == 'n':
        sys.exit("Can't continue without installing these packages. Exiting ...")
            

    if package_type == 'rpm':
        cmd = 'yum install -y epel-release'
        os.system(cmd)
        cmd = 'yum clean all'
        os.system(cmd)
        cmd = "yum install -y {0}".format(packages_str)
    else:
        os.system('apt-get update')
        cmd = "apt-get install -y {0}".format(packages_str)

    print "Installing package(s) with command: "+ cmd
    os.system(cmd)


if not os.path.exists(os.path.join(cur_dir, 'jsonmerge')):
    os.system('wget https://github.com/avian2/jsonmerge/archive/master.zip -O /tmp/jsonmerge-master.zip')
    os.system('unzip -qo /tmp/jsonmerge-master.zip -d /tmp')
    os.system('cp -r /tmp/jsonmerge-master/jsonmerge ' + cur_dir)

if not os.path.exists(os.path.join(cur_dir, 'setup')):
    os.system('wget https://github.com/GluuFederation/community-edition-setup/archive/master.zip -O /tmp/community-edition-setup-master.zip')
    os.system('unzip -qo /tmp/community-edition-setup-master.zip -d /tmp')
    os.system('mv /tmp/community-edition-setup-master {}/setup'.format(cur_dir))
    os.system('touch setup/__init__.py')


import jsonmerge


def checkIfAsimbaEntry(dn, new_entry):
    if 'ou=oxasimba' in dn:
        return True

    # this is Inbound SAML via Asimba authentication module
    if '!0011!D40C.1CA3' in dn:
        return True

    for objCls in ('oxAsimbaConfiguration', 'oxAsimbaIDP', 
            'oxAsimbaRequestorPool', 'oxAsimbaSPRequestor', 
            'oxAsimbaSelector'):
        if objCls in new_entry['objectClass']:
            return True


attribute_type_changes = {
                    'emailVerified': 'boolean',
                    'phoneNumberVerified': 'boolean',
                    'updatedAt': 'generalizedTime',
                    'picture': 'binary',
                    }
                    
                    


class GluuUpdater:
    def __init__(self):
        
        self.update_dir = cur_dir
        self.app_dir = os.path.join(self.update_dir,'app')
        self.war_dir = os.path.join(self.update_dir,'war')
        self.gluuBaseFolder = '/etc/gluu'
        self.certFolder = '/etc/certs'
        self.configFolder = '%s/conf' % self.gluuBaseFolder
        self.gluu_app_dir = '/opt/gluu/jetty'
        self.backup_time = time.strftime('%Y-%m-%d.%H:%M:%S')
        self.backup_folder = os.path.join(cur_dir, 'backup_{}'.format(self.backup_time))
        
        
        if not os.path.exists(self.backup_folder):
            os.mkdir(self.backup_folder)

        self.setup_dir = os.path.join(cur_dir, 'setup')
        self.template_dir = os.path.join(self.setup_dir, 'templates')
        self.scripts_ldif = os.path.join(self.template_dir, 'scripts.ldif')
        self.current_ldif_fn = os.path.join(cur_dir, 'gluu.ldif')
        self.processed_ldif_fn = os.path.join(cur_dir, 'gluu_noinum.ldif')
        self.extensionFolder = os.path.join(self.setup_dir, 'static/extension')
        self.oxtrust_api_ldif = os.path.join(self.template_dir, 'oxtrust_api.ldif')
        self.backup_time = time.ctime().replace(' ','_')
        self.newDns = []
        self.enabled_scripts = []
        self.current_version = '4.0.b1'

        self.script_replacements = {
                '2DAF-F995': '2DAF-F9A5'
            }



    def dump_current_db(self):
        print "Dumping ldap to gluu.ldif"
        os.system('cp -r -f /opt/opendj /opt/opendj.bak_'+self.backup_time)
        os.system('/opt/opendj/bin/ldapsearch -X -Z -D "cn=directory manager" -w {} -h localhost -p 1636 -b "o=gluu" "Objectclass=*" > ./gluu.ldif'.format(setupObject.ldapPass))

    def update_schema(self):
        print "Updating schema"
        new_schema = os.path.join(self.setup_dir, 'static/opendj/101-ox.ldif')
        target_schema = os.path.join(setupObject.ldapBaseFolder, 'config/schema/101-ox.ldif')
        shutil.copy(new_schema, target_schema)
        os.system('chown ldap:ldap ' + target_schema)


    def download_apps(self):
        for d in (self.app_dir, self.war_dir):
            if not os.path.exists(d):
                os.mkdir(d)

        os.system('wget -nv https://ox.gluu.org/maven/org/gluu/oxshibbolethIdp/{0}/oxshibbolethIdp-{0}.war -O {1}/idp.war'.format(self.current_version, self.war_dir))
        os.system('wget -nv https://ox.gluu.org/maven/org/gluu/oxtrust-server/{0}/oxtrust-server-{0}.war -O {1}/identity.war'.format(self.current_version, self.war_dir))
        os.system('wget -nv https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}/oxauth-server-{0}.war -O {1}/oxauth.war'.format(self.current_version, self.war_dir))
        os.system('wget -nv https://ox.gluu.org/maven/org/gluu/oxShibbolethStatic/{0}/oxShibbolethStatic-{0}.jar -O {1}/shibboleth-idp.jar'.format(self.current_version, self.app_dir))
        os.system('wget -nv https://ox.gluu.org/maven/org/gluu/oxShibbolethKeyGenerator/{0}/oxShibbolethKeyGenerator-{0}.jar -O {1}/idp3_cml_keygenerator.jar'.format(self.current_version, self.app_dir))
        os.system('wget -nv https://ox.gluu.org/npm/passport/passport-4.0.0.tgz -O {0}/passport.tgz'.format(self.app_dir))
        os.system('wget -nv https://ox.gluu.org/npm/passport/passport-version_4.0.b1-node_modules.tar.gz -O {0}/passport-node_modules.tar.gz'.format(self.app_dir))
        os.system('wget -nv https://fossies.org/linux/www/jetty-distribution-9.4.19.v20190610.tar.gz -O {0}/jetty-distribution-9.4.19.v20190610.tar.gz'.format(self.app_dir))

        #https://github.com/AdoptOpenJDK/openjdk11-binaries/releases/download/jdk-11.0.4%2B11/OpenJDK11U-jdk_x64_linux_hotspot_11.0.4_11.tar.gz
        #https://nodejs.org/dist/v12.6.0/node-v12.6.0-linux-x64.tar.xz
        #https://fossies.org/linux/www/jetty-distribution-9.4.19.v20190610.tar.gz


    def update_war(self):

        os.environ['PATH'] += ':/opt/jre/bin/java'

        for app in os.listdir(self.gluu_app_dir):
            war_app = app+'.war'
            new_war_app_file = os.path.join(self.war_dir, war_app)
            if os.path.exists(new_war_app_file):
                app_dir = os.path.join(self.gluu_app_dir, app, 'webapps')
                cur_war = os.path.join(app_dir, war_app)
                if os.path.exists(cur_war):
                    print "Backing up", war_app, "to", self.backup_folder
                    shutil.copy(cur_war, self.backup_folder)
                    
                    resources_dir = os.path.join(self.gluu_app_dir, app, 'resources')
                    if not os.path.exists(resources_dir):
                        os.mkdir(resources_dir)
                    
                    start_ini = '/opt/gluu/jetty/{}/start.ini'.format(app)
                    print "START INI", start_ini
                    if os.path.exists(start_ini):
                        os.remove(start_ini)
                        

                    setupObject.run([
                        '/opt/jre/bin/java', '-jar', 
                        '/opt/jetty/start.jar', 
                        'jetty.home=/opt/jetty',
                        'jetty.base=' + os.path.join(self.gluu_app_dir, app), 
                        '--add-to-start=' + setupObject.jetty_app_configuration[app]['jetty']['modules']], 
                        None, os.environ)

                    os.system('chown jetty:jetty ' + resources_dir)
                    
                print "Updating", war_app
                shutil.copy(new_war_app_file, app_dir)

        shutil.copy('/opt/dist/gluu/idp3_cml_keygenerator.jar', self.backup_folder)
        shutil.copy(os.path.join(self.app_dir, 'idp3_cml_keygenerator.jar'), '/opt/dist/gluu/')

    def update_default_settings(self):
        for service in ('casa', 'identity', 'idp', 'oxauth', 'oxauth-rp'):
            target_fn = os.path.join('/etc/default', service)
            if os.path.exists(target_fn):
                tmp_config_fn = os.path.join(self.setup_dir, 'templates/jetty', service)
                tmp_config = self.render_template(tmp_config_fn)
                with open(target_fn,'w') as w:
                    w.write(tmp_config)

    def parse_current_ldif(self):
        
        print "Parsing LDIF File. This may take a while"
        
        self.ldif_parser = MyLDIF(open(self.current_ldif_fn))
        self.ldif_parser.parse()

        self.inumOrg_ou = 'o={}'.format(self.ldif_parser.inumOrg)
        self.inumApllience_inum = 'inum={}'.format(self.ldif_parser.inumApllience)

        print "inumOrg", self.ldif_parser.inumOrg
        print "inumAppliance", self.ldif_parser.inumApllience
        print

    def add_new_scripts(self):

        print "Replacing current custom scripts with latest scripts"

        for extensionType in os.listdir(self.extensionFolder):
            extensionTypeFolder = os.path.join(self.extensionFolder, extensionType)
            if not os.path.isdir(extensionTypeFolder):
                continue

            for scriptFile in os.listdir(extensionTypeFolder):
                scriptFilePath = os.path.join(extensionTypeFolder, scriptFile)
                base64ScriptFile = setupObject.generate_base64_file(scriptFilePath, 1)
                extensionScriptName = '{}_{}'.format(extensionType, os.path.splitext(scriptFile)[0])
                extensionScriptName = extensionScriptName.decode('utf-8').lower()
                setupObject.templateRenderingDict[extensionScriptName] = base64ScriptFile

        self.add_template(self.scripts_ldif)


    def render_template(self, tmp_file):
        data_dict = setupObject.__dict__
        data_dict.update(setupObject.templateRenderingDict)
        
        ldif_temp = open(tmp_file).read()
        ldif_temp = setupObject.fomatWithDict(ldif_temp,  data_dict)
        
        return ldif_temp

    def add_template(self, tmp_file):

        ldif_temp = self.render_template(tmp_file)

        ldif_io = io.StringIO(ldif_temp.decode('utf-8'))
        ldif_io.seek(0)

        parser = pureLDIFParser(ldif_io)
        parser.parse()

        for scr_dn in parser.entries:
            
            if 'inum' in parser.entries[scr_dn]:
                if parser.entries[scr_dn]['inum'][0] in ('2DAF-F995', '2DAF-F9A5'):
                    oxConfigurationProperty = json.loads(parser.entries[scr_dn]['oxConfigurationProperty'][0])
                    
                    tmp_ = [self.inum2uuid(v.strip()) for v in oxConfigurationProperty['value2'].split(',')]
                    oxConfigurationProperty['value2'] = ', '.join(tmp_)
                    parser.entries[scr_dn]['oxConfigurationProperty'] = [ json.dumps(oxConfigurationProperty) ]
                if parser.entries[scr_dn]['inum'][0] in self.enabled_scripts:
                    parser.entries[scr_dn]['oxEnabled'] = ['true']
            
            self.newDns.append(scr_dn)
            self.write2ldif(scr_dn, parser.entries[scr_dn])
        
    def add_new_entries(self):
        
        self.add_template(self.oxtrust_api_ldif)


    def inum2uuid(self, s):

        tmps = s.replace(self.ldif_parser.inumApllience,'').replace(self.ldif_parser.inumOrg,'')

        for x in re.findall('(!00[0-9a-fA-F][0-9a-fA-F]!)', tmps):
            tmps = tmps.replace(x, '')
        
        for x in re.findall('(![0-9a-fA-F]{4}\.)', tmps):
            tmps = tmps.replace(x, x.strip('!').strip('.') +'-')

        for x in re.findall('([0-9a-fA-F]{4}\.[0-9a-fA-F]{4})', tmps):
            tmps = tmps.replace(x, x.replace('.','-'))

        for x in re.findall('(00[0-9a-fA-F][0-9a-fA-F]-)', tmps):
            tmps = tmps.replace(x, '')

        for x in re.findall(',\w+=,',tmps):
            tmps = tmps.replace(x, ',')

        return tmps


    def add_missing_attributes(self):
        
        with open(os.path.join(self.template_dir, 'attributes.ldif')) as attributes_file:

            attributes_parser = pureLDIFParser(attributes_file)
            attributes_parser.parse()
            
            for attr_dn in attributes_parser.entries:
                if not attr_dn in self.newDns:
                    self.write2ldif(attr_dn, attributes_parser.entries[attr_dn])


    def write2ldif(self, new_dn, new_entry):
        self.newDns.append(new_dn)
        self.ldif_writer.unparse(new_dn, new_entry)



    def do_config_changes(self, js_conf, changes):
        for config_element in changes:

            for key, change_type, how_change, value in changes:
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


    def create_idp_client(self):

        setupObject.idp_client_id = '0008-'+ str(uuid.uuid4())
        setupObject.idpClient_pw = setupObject.getPW()
        setupObject.idpClient_encoded_pw = setupObject.obscure(setupObject.idpClient_pw)

        dn = "inum=%(idp_client_id)s,ou=clients,o=gluu" % setupObject.__dict__

        new_entry = { 'objectClass': ['oxAuthClient', 'top'],
                  'displayName': ['IDP client'],
                  'inum': [setupObject.idp_client_id],
                  'oxAuthClientSecret': [setupObject.idpClient_encoded_pw],
                  'oxAuthAppType': ['web'],
                  'oxAuthResponseType': ['code'],
                  'oxAuthGrantType': ['authorization_code','refresh_token'],
                  'oxAuthScope': [ 'inum=10B2,ou=scopes,o=gluu',
                                   'inum=764C,ou=scopes,o=gluu',
                                   'inum=F0C4,ou=scopes,o=gluu',
                                ],
                  'oxAuthRedirectURI': ['https://%(hostname)s/idp/Authn/oxAuth' % setupObject.__dict__],
                  'oxAuthLogoutURI': ['https://%(hostname)s/idp/Authn/oxAuth/ssologout' % setupObject.__dict__],
                  'oxAuthPostLogoutRedirectURI': ['https://%(hostname)s/idp/profile/Logout' % setupObject.__dict__],
                  'oxAuthLogoutURI': ['https://%(hostname)s/identity/logout' % setupObject.__dict__],
                  'oxAuthTokenEndpointAuthMethod': ['client_secret_basic'],
                  'oxAuthIdTokenSignedResponseAlg': ['HS256'],
                  'oxAuthTrustedClient': ['true'],
                  'oxAuthSubjectType': ['public'],
                  'oxPersistClientAuthorizations': ['false'],
                  'oxAuthLogoutSessionRequired': ['true'],
                  }

        self.write2ldif(dn, new_entry)

        return new_entry

    def process_ldif(self):

        print "Processing ldif. This may take a while ...."

        attributes_parser = pureLDIFParser(open(os.path.join(self.template_dir, 'attributes.ldif')))
        attributes_parser.parse()

        processed_fp = open(self.processed_ldif_fn,'w')
        self.ldif_writer = LDIFWriter(processed_fp)


        for dn in self.ldif_parser.entries:

            new_entry = self.ldif_parser.entries[dn]

            # we don't need existing scripts won't work in 4.0, passing
            if 'oxCustomScript' in new_entry['objectClass']:
                if 'true' in new_entry['gluuStatus']:
                    scr_inum = self.inum2uuid(new_entry['inum'][0])
                    self.enabled_scripts.append(self.script_replacements.get(scr_inum, scr_inum))
                continue

            # we don't need existing tokens, passing
            elif 'oxAuthGrant' in new_entry['objectClass']:
                continue
            
            elif 'oxAuthExpiration' in new_entry:
                continue
            #elif 'oxAuthTokenCode' in new_entry:
            #    continue
            #elif 'oxTicket' in new_entry:
            #    continue

            #we won't have asimba, passing asimba related entries
            if checkIfAsimbaEntry(dn, new_entry):
                continue


            if 'ou' in new_entry and new_entry['ou'][0] in ('uma_permission', 'uma_rpt'):
                continue


            dne = explode_dn(dn)

            if self.inumOrg_ou in dne:
                dne.remove(self.inumOrg_ou)

            if self.inumApllience_inum in dne:
                dne.remove(self.inumApllience_inum)
                dne.remove('ou=appliances')

                if dn == self.ldif_parser.inumApllience_dn:
                    dne.insert(0,'ou=configuration')
                    new_entry['ou'] = 'configuration'
                    new_entry['objectClass'].insert(1, 'organizationalUnit')
                    
                
            new_dn = ','.join(dne)

            if dn == self.ldif_parser.inumOrg_dn:
                new_entry['o'][0] = 'gluu'

            elif dn == self.ldif_parser.inumApllience_dn:
                new_entry['objectClass'].remove('gluuAppliance')
                new_entry['objectClass'].insert(1, 'gluuConfiguration')
                new_entry['ou'] = ['configuration']
                new_entry.pop('inum')

                oxIDPAuthentication = json.loads(new_entry['oxIDPAuthentication'][0])
                oxIDPAuthentication_config = json.loads(oxIDPAuthentication['config'])
                oxIDPAuthentication_config['baseDNs'][0] = 'ou=people,o=gluu'
                oxIDPAuthentication['config'] = json.dumps(oxIDPAuthentication_config)
                new_entry['oxIDPAuthentication'][0] = json.dumps(oxIDPAuthentication, indent=2)

                for bool_attr in (
                                'gluuPassportEnabled',
                                'gluuManageIdentityPermission',
                                'gluuOrgProfileMgt',
                                'gluuScimEnabled',
                                'gluuVdsCacheRefreshEnabled',
                                'passwordResetAllowed',
                                ):
                    if bool_attr in new_entry:
                        
                        if new_entry[bool_attr][0] == 'enabled':
                            new_entry[bool_attr] = ['true']
                        else:
                            new_entry[bool_attr] = ['false']


            if 'oxAuthConfDynamic' in new_entry:
                oxAuthConfDynamic = json.loads(new_entry['oxAuthConfDynamic'][0])
                
                oxAuthConfDynamic_config_changes = [
                
                        ('organizationInum', 'remove', 'entry', None),
                        ('applianceInum', 'remove', 'entry', None),
                
                        ("baseEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1".format(setupObject.hostname)),
                        ("authorizationEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/authorize".format(setupObject.hostname)),
                        ("tokenEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/token".format(setupObject.hostname)),
                        ("userInfoEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/userinfo".format(setupObject.hostname)),
                        ("clientInfoEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/clientinfo".format(setupObject.hostname)),
                        ("checkSessionIFrame", 'change', 'entry', "https://{0}/oxauth/opiframe".format(setupObject.hostname)),
                        ("endSessionEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/end_session".format(setupObject.hostname)),
                        ("jwksUri", 'change', 'entry', "https://{0}/oxauth/restv1/jwks".format(setupObject.hostname)),
                        ("registrationEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/register".format(setupObject.hostname)),
                        ("openIdDiscoveryEndpoint", 'change', 'entry', "https://{0}/.well-known/webfinger".format(setupObject.hostname)),
                        ("openIdConfigurationEndpoint", 'change', 'entry', "https://{0}/.well-known/openid-configuration".format(setupObject.hostname)),
                        ("idGenerationEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/id".format(setupObject.hostname)),
                        ("introspectionEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/introspection".format(setupObject.hostname)),
                        ("umaConfigurationEndpoint", 'change', 'entry', "https://{0}/oxauth/restv1/uma2-configuration".format(setupObject.hostname)),
                        ("checkSessionIFrame", 'change', 'entry', "https://{0}.gluu.org/oxauth/opiframe.htm".format(setupObject.hostname)),

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
                        
                        ('fido2Configuration', 'add', 'entry', {
                                                                'authenticatorCertsFolder':'{0}/authenticator_cert'.format(setupObject.fido2ConfigFolder),
                                                                'mdsCertsFolder':'{0}/mds/cert'.format(setupObject.fido2ConfigFolder),
                                                                'mdsTocsFolder':'{0}/mds/toc'.format(setupObject.fido2ConfigFolder),
                                                                'serverMetadataFolder':'{0}/server_metadata',
                                                                'userAutoEnrollment':False,
                                                                'unfinishedRequestExpiration':120,
                                                                'authenticationHistoryExpiration':1296000,
                                                                'disableFido2':True,
                                                                }),
                        ('loginPage', 'remove', 'entry', None),
                        ('authorizationPage', 'remove', 'entry', None),
                        ('umaRequesterPermissionTokenLifetime', 'remove', 'entry', None),
                        ('validateTokenEndpoint', 'remove', 'entry', None),
                        ('shortLivedAccessTokenLifetime', 'remove', 'entry', None),
                        ('longLivedAccessTokenLifetime', 'remove', 'entry', None),
                        ('sessionStateHttpOnly', 'remove', 'entry', None),
                        ('velocityLog', 'remove', 'entry', None),
                        ('dynamicRegistrationExpirationTime', 'change', 'entry', -1),
                        ('userInfoSigningAlgValuesSupported', 'add', 'element', 'PS256'),
                        ('userInfoSigningAlgValuesSupported', 'add','element', 'PS384'),
                        ('userInfoSigningAlgValuesSupported', 'add','element', 'PS512'),
                        ('idTokenSigningAlgValuesSupported', 'add','element', 'PS256'),
                        ('idTokenSigningAlgValuesSupported', 'add','element', 'PS384'),
                        ('idTokenSigningAlgValuesSupported', 'add','element', 'PS512'),
                        
                        ('shareSubjectIdBetweenClientsWithSameSectorId', 'add',  'entry', True),

                    ]
    
                self.do_config_changes(oxAuthConfDynamic, oxAuthConfDynamic_config_changes)

                new_entry['oxAuthConfDynamic'][0] = json.dumps(oxAuthConfDynamic, indent=2)
                
                
                ##########################
                
                
                oxAuthConfDynamic['tokenRevocationEndpoint'] = 'https://%(hostname)s/oxauth/restv1/revoke' % setupObject.__dict__
                oxAuthConfDynamic['responseModesSupported'] = ['query', 'fragment', 'form_post']
                
                for sign_alg in ('PS256', 'PS384', 'PS512'):
                    if sign_alg in oxAuthConfDynamic['userInfoSigningAlgValuesSupported']:
                        oxAuthConfDynamic['userInfoSigningAlgValuesSupported'].remove(sign_alg)
                    if sign_alg in oxAuthConfDynamic['idTokenSigningAlgValuesSupported']:
                        oxAuthConfDynamic['idTokenSigningAlgValuesSupported'].remove(sign_alg)
                    if sign_alg in oxAuthConfDynamic['requestObjectSigningAlgValuesSupported']:
                        oxAuthConfDynamic['requestObjectSigningAlgValuesSupported'].remove(sign_alg)
                    if sign_alg in oxAuthConfDynamic['tokenEndpointAuthSigningAlgValuesSupported']:
                        oxAuthConfDynamic['tokenEndpointAuthSigningAlgValuesSupported'].remove(sign_alg)
                    
                oxAuthConfDynamic['cleanServiceBatchChunkSize'] = 1000
                
                oxAuthConfDynamic['authenticationFilters'][0]['baseDn'] = 'ou=people,o=gluu'
                oxAuthConfDynamic['authenticationFilters'][1]['baseDn'] = 'ou=people,o=gluu'
                oxAuthConfDynamic['clientAuthenticationFilters'][0]['baseDn'] = 'ou=clients,o=gluu'
                
                oxAuthConfDynamic['shareSubjectIdBetweenClientsWithSameSectorId'] = True

                oxAuthConfStatic = {
                                    "baseDn":{
                                        "configuration":"ou=configuration,o=gluu",
                                        "people":"ou=people,o=gluu",
                                        "groups":"ou=groups,o=gluu",
                                        "clients":"ou=clients,o=gluu",
                                        "tokens":"ou=tokens,o=gluu",
                                        "scopes":"ou=scopes,o=gluu",
                                        "attributes":"ou=attributes,o=gluu",
                                        "scripts": "ou=scripts,o=gluu",
                                        "umaBase":"ou=uma,o=gluu",
                                        "umaPolicy":"ou=policies,ou=uma,o=gluu",
                                        "u2fBase":"ou=u2f,o=gluu",
                                        "metric":"ou=statistic,o=metric",
                                        "sectorIdentifiers": "ou=sector_identifiers,o=gluu"
                                    }
                                }


                new_entry['oxAuthConfStatic'][0] = json.dumps(oxAuthConfStatic, indent=2)


            elif 'oxTrustConfApplication' in new_entry:
                oxTrustConfApplication = json.loads(new_entry['oxTrustConfApplication'][0])

                oxTrustConfApplication_config_changes = [
                    ('orgInum', 'remove', 'entry', None),
                    ('applianceInum', 'remove', 'entry', None),
                    ("baseEndpoint", 'change', 'entry', "https://{0}/identity/restv1".format(setupObject.hostname)),
                    ("loginRedirectUrl", 'change', 'entry', "https://{0}/identity/authentication/getauthcode".format(setupObject.hostname)),
                    ("scimUmaResourceId", 'change', 'entry', "0f13ae5a-135e-4b01-a290-7bbe62e7d40f"),
                    ("scimUmaScope", 'change', 'entry', "https://{0}/oxauth/restv1/uma/scopes/scim_access".format(setupObject.hostname)),
                    ("passportUmaResourceId", 'change', 'entry', "0f963ecc-93f0-49c1-beae-ad2006abbb99"),
                    ("passportUmaScope", 'change', 'entry', "https://{0}/oxauth/restv1/uma/scopes/passport_access".format(setupObject.hostname)),
                    ('scimTestModeAccessToken','remove', 'entry', None),
                    ('ScimProperties','remove', 'entry', None),
                    ('ScimProperties','add', 'entry', {'maxCount': 200}),
                    ('passwordResetRequestExpirationTime', 'add', 'entry', 600),
                    ('oxTrustApiTestMode', 'add', 'entry', False),
                    
                    ('applicationUrl', 'add', 'entry', oxTrustConfApplication.pop('applianceUrl')),
                    ('updateStatus', 'add', 'entry', oxTrustConfApplication.pop('updateApplianceStatus')),
                    
                    ('loginRedirectUrl', 'add', 'entry', 'https://%(hostname)s/identity/authcode.htm' % setupObject.__dict__),
                    ('logoutRedirectUrl', 'add', 'entry','https://%(hostname)s/identity/finishlogout.htm' % setupObject.__dict__),
                    ('apiUmaClientId', 'add', 'entry','%(oxtrust_resource_server_client_id)s' % setupObject.__dict__),
                    ('apiUmaClientKeyId', 'add', 'entry', ''),
                    ('apiUmaResourceId', 'add', 'entry', '%(oxtrust_resource_id)s' % setupObject.__dict__),
                    ('apiUmaScope', 'add', 'entry','https://%(hostname)s/oxauth/restv1/uma/scopes/oxtrust-api-read' % setupObject.__dict__),
                    ('apiUmaClientKeyStoreFile', 'add', 'entry','%(api_rs_client_jks_fn)s' % setupObject.__dict__),
                    ('apiUmaClientKeyStorePassword', 'add', 'entry', '%(api_rs_client_jks_pass_encoded)s' % setupObject.__dict__),
                    
                    ]

                self.do_config_changes(oxTrustConfApplication, oxTrustConfApplication_config_changes)


                for cli in ('scimUmaClientId', 'passportUmaClientId', 'oxAuthClientId'):
                    oxTrustConfApplication[cli] = self.inum2uuid(oxTrustConfApplication[cli])
                

                new_entry['oxTrustConfApplication'][0] = json.dumps(oxTrustConfApplication, indent=2)
                
                if 'oxTrustConfAttributeResolver' in new_entry:
                    oxTrustConfAttributeResolver = json.loads(new_entry['oxTrustConfAttributeResolver'][0])
                    for name_id in oxTrustConfAttributeResolver['nameIdConfigs']:
                        name_id.pop('name')
                        if 'persistent' in name_id['nameIdType']:
                            name_id['nameIdType'] = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
                        elif 'emailAddress' in name_id['nameIdType']:
                            name_id['nameIdType'] = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
                        else:
                            name_id['nameIdType'] = 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName'
                
                    new_entry['oxTrustConfAttributeResolver'][0] = json.dumps(oxTrustConfAttributeResolver)
                

                if not 'oxTrustConfAttributeResolver' in new_entry:
                    new_entry['oxTrustConfAttributeResolver'] = ['{"nameIdConfigs":[{"sourceAttribute":"mail","nameIdType":"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress","enabled":true},{"sourceAttribute":"birthdate","nameIdType":"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent","enabled":true},{"sourceAttribute":"address","nameIdType":"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName","enabled":false}]}']


                oxTrustConfImportPerson = json.loads(new_entry['oxTrustConfImportPerson'][0])
        
                for ox_map in oxTrustConfImportPerson['mappings']:
                    if ox_map['ldapName'] == 'gluuStatus':
                        break
                else:
                    oxTrustConfImportPerson['mappings'].append(
                                            {
                                            "ldapName": "gluuStatus", 
                                            "displayName": "User Status", 
                                            "dataType": "string", 
                                            "required": False
                                            }
                                            )
                    
                    new_entry['oxTrustConfImportPerson'][0] =  json.dumps(oxTrustConfImportPerson, indent=2)


            elif 'oxIDPAuthentication' in new_entry:
                oxIDPAuthentication = json.loads(new_entry['oxIDPAuthentication'][0])
                oxIDPAuthentication['config'] = json.loads(oxIDPAuthentication['config'])                
                new_entry['oxIDPAuthentication'][0] = json.dumps(oxIDPAuthentication, indent=2)


            if 'ou=configuration,o=gluu' == new_dn:
                
                
                # we need to set authentication mode to ldap
                new_entry['oxAuthenticationMode'] =  ['auth_ldap_server']
                new_entry['oxTrustAuthenticationMode'] = ['auth_ldap_server']
                

                if not 'oxCacheConfiguration' in new_entry:
                    continue
                else:
                    oxCacheConfiguration_cur = json.loads(new_entry['oxCacheConfiguration'][0])
                    oxCacheConfiguration_new = {'cacheProviderType': 'IN_MEMORY', 'nativePersistenceConfiguration': {'defaultPutExpiration': 60, 'defaultCleanupBatchSize': 25}, 'redisConfiguration': {'useSSL': False, 'defaultPutExpiration': 60, 'servers': 'localhost:6379', 'sslTrustStoreFilePath': '', 'decryptedPassword': None, 'password': None, 'redisProviderType': 'STANDALONE'}, 'memcachedConfiguration': {'servers': 'localhost:11211', 'defaultPutExpiration': 60, 'bufferSize': 32768, 'maxOperationQueueLength': 100000, 'connectionFactoryType': 'DEFAULT'}, 'inMemoryConfiguration': {'defaultPutExpiration': 60}}
                    oxCacheConfiguration = jsonmerge.merge(oxCacheConfiguration_new, oxCacheConfiguration_cur)
                    new_entry['oxCacheConfiguration'] = [ json.dumps(oxCacheConfiguration) ]
                        

            for p in ('oxAuthClaim', 'owner', 'oxAssociatedClient', 
                        'oxAuthUmaScope', 'gluuManagerGroup', 'member', 
                        'oxPolicyScriptDn','oxScriptDn', 'oxAuthScope',
                        'memberOf',):

                if p in new_entry:
                    for i, oac in enumerate(new_entry[p][:]):
                        new_entry[p][i] = oac.replace(self.inumOrg_ou+',','')


            for e in new_entry:
                for i, se in enumerate(new_entry[e][:]):
                    if 'inum=' in se:
                        new_entry[e][i] = self.inum2uuid(se)


            if 'inum' in new_entry:

                new_entry['inum'] = [self.inum2uuid(new_entry['inum'][0])]
                new_dn = self.inum2uuid(new_dn)

                if new_entry['inum'][0] in ['8CAD-B06D', '8CAD-B06E']:
                    if 'oxRevision' in new_entry:
                        new_entry.pop('oxRevision')
                
                    if 'owner' in new_entry:
                        new_entry.pop('owner')
                
                    new_entry['oxScopeType'] = ['uma']

                elif new_entry['inum'][0] == 'DF6B-4902' or new_entry['displayName'][0] == 'oxTrust Admin GUI':
                    new_entry['oxAuthLogoutURI'] = [ 'https://%(hostname)s/identity/ssologout.htm' % setupObject.__dict__ ]
                    new_entry['oxAuthRedirectURI'] = [ 'https://%(hostname)s/identity/scim/auth' % setupObject.__dict__ ,
                                                    'https://%(hostname)s/identity/authcode.htm' % setupObject.__dict__ ,
                                                    'https://%(hostname)s/oxauth/restv1/uma/gather_claims?authentication=true'  % setupObject.__dict__ ,
                                                    ]
                    new_entry['oxClaimRedirectURI'] = [ 'https://%(hostname)s/oxauth/restv1/uma/gather_claims' % setupObject.__dict__ ]
                    new_entry['oxAuthPostLogoutRedirectURI'] = [ 'https://%(hostname)s/identity/finishlogout.htm' % setupObject.__dict__ ]

                elif new_entry['inum'][0] == '6D99':
                    new_entry['oxScopeType'] = ['openid']

                elif new_entry['inum'][0] == 'D2E0':
                    new_entry['oxAuthClaimName'] = ['member_of']
                    


            if 'oxPolicyScriptDn' in new_entry:
                new_entry['oxUmaPolicyScriptDn'] = [new_entry['oxPolicyScriptDn'][0]]
                new_entry.pop('oxPolicyScriptDn')
    

            if new_dn == 'ou=oxidp,ou=configuration,o=gluu':
                oxConfApplication = json.loads(new_entry['oxConfApplication'][0])
                oxConfApplication['openIdClientId'] =  self.inum2uuid(oxConfApplication['openIdClientId'])

                if self.ldif_parser.idp_client:
                    idp_entry = self.ldif_parser.entries[str(self.ldif_parser.idp_client)]
                    openIdClientId =  self.inum2uuid(idp_entry['inum'][0])
                    oxAuthClientSecret = idp_entry['oxAuthClientSecret'][0]
                else:
                    idp_entry = self.create_idp_client()
                    openIdClientId = idp_entry['inum'][0]
                    oxAuthClientSecret = idp_entry['oxAuthClientSecret'][0]
                    
                oxConfApplication_changes = (
                            ('openIdClientId', 'add', 'entry', openIdClientId),
                            ('openIdClientPassword', 'add', 'entry', oxAuthClientSecret),
                            ('openIdRedirectUrl', 'add', 'entry', 'https://%(hostname)s/idp/Authn/oxAuth' % setupObject.__dict__ ),
                            ('openIdPostLogoutRedirectUri', 'add', 'entry', 'https://%(hostname)s/idp/profile/Logout' % setupObject.__dict__ ),
                            )
                
                self.do_config_changes(oxConfApplication, oxConfApplication_changes)

                new_entry['oxConfApplication'] = [ json.dumps(oxConfApplication, indent=2) ]
                

            if new_dn == 'o=gluu':
                if 'gluuAddPersonCapability' in new_entry:
                    new_entry.pop('gluuAddPersonCapability')
                if 'scimAuthMode' in new_entry:
                    new_entry.pop('scimAuthMode')
                if 'scimStatus' in new_entry:
                    new_entry.pop('scimStatus')
                if not 'organization' in new_entry['objectClass']:
                    new_entry['objectClass'].append('organization')
            
            
            # check for objectClass
            if 'oxAuthCustomScope' in new_entry['objectClass']:
                new_entry['oxId']  = new_entry['displayName']
                new_entry.pop('displayName')

            elif 'oxAuthUmaScopeDescription' in new_entry['objectClass']:
                new_entry['objectClass'].remove('oxAuthUmaScopeDescription')
                new_entry['objectClass'].append('oxAuthCustomScope')
                new_entry['oxScopeType'] = ['uma']
                
                if new_entry['inum'][0] == '8CAD-B06D':
                    new_entry['oxId'] = [ 'https://%(hostname)s/oxauth/restv1/uma/scopes/scim_access' % setupObject.__dict__ ]

                new_dn_e = explode_dn(new_dn)
                if 'ou=uma' in new_dn_e:
                    new_dn_e.remove('ou=uma')
                new_dn = ','.join(new_dn_e)

            elif 'oxPassportConfiguration' in  new_entry['objectClass']:
                self.fix_passport_config(new_dn, new_entry)
                continue
            
            elif 'gluuSAMLconfig' in  new_entry['objectClass']:
                new_entry['o'] = ['o=gluu']

            elif 'oxAuthClient' in new_entry['objectClass']:
                if new_entry['displayName'] == 'IDP client':
                    new_entry['oxAuthLogoutURI'] = ['https://%(hostname)s/idp/Authn/oxAuth/ssologout' % setupObject.__dict__ ]
                    new_entry['oxAuthLogoutURI'] = ['https://%(hostname)s/idp/Authn/oxAuth/ssologout' % setupObject.__dict__ ]
                    new_entry['oxAuthPostLogoutRedirectURI'] = ['https://%(hostname)s/idp/profile/Logout' % setupObject.__dict__ ]
                    new_entry['oxAuthPostLogoutRedirectURI'] = ['https://%(hostname)s/idp/profile/Logout' % setupObject.__dict__ ]

            if 'oxAuthUmaScope' in new_entry:
                tmp_dn_e = explode_dn(new_entry['oxAuthUmaScope'][0])
                if 'ou=uma' in tmp_dn_e:
                    tmp_dn_e.remove('ou=uma')
                new_entry['oxAuthUmaScope'] = [ ','.join(tmp_dn_e) ]


            #Fix attributes
            if 'gluuAttribute' in new_entry['objectClass']:
                new_entry['gluuSAML1URI'] = [ 'urn:mace:dir:attribute-def:' + new_entry['gluuAttributeName'][0] ]
                new_entry['gluuSAML2URI'] = attributes_parser.entries[new_dn]['gluuSAML2URI']
                if  new_entry['gluuAttributeName'][0] in attribute_type_changes:
                    new_entry['gluuAttributeType'] = attribute_type_changes[new_entry['gluuAttributeName'][0]]

            #Write modified entry to ldif
            self.newDns.append(new_dn)
            self.write2ldif(new_dn, new_entry)

        
        self.add_new_scripts()
        self.add_new_entries()
        self.add_missing_attributes()


        self.write2ldif('ou=resetPasswordRequests,o=gluu', {'objectClass': ['top', 'organizationalUnit'], 'ou': ['resetPasswordRequests']})
        self.write2ldif('ou=metric,o=gluu', {'objectClass':['top','organizationalunit'], 'ou': ['metric'] })
        self.write2ldif('ou=tokens,o=gluu', {'objectClass':['top','organizationalunit'], 'ou': ['tokens'] })
        #self.write2ldif('ou=pct,ou=uma,o=gluu', {'objectClass':['top','organizationalunit'], 'ou': ['pct'] })


        processed_fp.close()

    def update_passport(self):
        
        if not os.path.exists('/opt/gluu/node/passport'):
            return
        
        print "Updating Passport"
        
        print "Stopping passport server"
        
        setupObject.run_service_command('passport', 'stop')

        #print "Downloading passport server"
        #os.system('wget https://ox.gluu.org/npm/passport/passport-4.0.0.tgz -O passport.tgz')
        
        #print "Downloading passport node libraries"
        #os.system('wget https://ox.gluu.org/npm/passport/passport-master-node_modules.tar.gz -O passport-master-node_modules.tar.gz')


        print "Removing existing passport server and node libraries"
        os.system('rm -r -f /opt/gluu/node/passport/server/mappings')
        os.system('rm -r -f /opt/gluu/node/passport/server/utils')
        os.system('rm -r -f /opt/gluu/node/passport/node_modules')

        print "Extracting passport.tgz into /opt/gluu/node/passport"
        os.system('tar --strip 1 -xzf {0}/passport.tgz -C /opt/gluu/node/passport --no-xattrs --no-same-owner --no-same-permissions'.format(self.app_dir))
 
        print "Extracting passport node modules"
        modules_dir = '/opt/gluu/node/passport/node_modules'
        if not os.path.exists(modules_dir):
            os.mkdir(modules_dir)
        os.system('tar --strip 1 -xzf {0}/passport-node_modules.tar.gz -C {1} --no-xattrs --no-same-owner --no-same-permissions'.format(self.app_dir,modules_dir))

        log_dir = '/opt/gluu/node/passport/server/logs'

        if not os.path.exists(log_dir): 
            os.mkdir(log_dir)

        os.system('chown -R node:node /opt/gluu/node/passport/')

    def fix_passport_config(self, new_dn, new_entry):
        
        setupObject.generate_passport_configuration()
        
        
        passportStrategyId_mapping = {
                'github': 'passport-github',
                'openidconnect-default': 'passport-openidconnect',
                'twitter': 'passport-twitter',
                'yahoo': 'passport-yahoo-oauth2',
                'tumblr': 'passport-tumblr',
                'linkedin': 'passport-linkedin-oauth2',
                'google': 'passport-google-oauth2',
                'facebook': 'passport-facebook',
                'dropbox': 'passport-dropbox-oauth2',
                'windowslive': 'passport-windowslive',
            }
        
        providers = []

        for passport_configuration in new_entry['gluuPassportConfiguration']:

            gluuPassportConfiguration = json.loads(passport_configuration)
            
            strategy = gluuPassportConfiguration['strategy']


            (key, val) = ('value1', 'value2') if 'value1' in gluuPassportConfiguration['fieldset'][0] else ('key','value')

            field_key = { field[key]: field[val] for field in  gluuPassportConfiguration['fieldset'] }


            provider =  {
                  'displayName': strategy, 
                  'passportStrategyId': passportStrategyId_mapping[strategy],
                  'requestForEmail': False, 
                  'enabled': True, 
                  'mapping': strategy if strategy in ('dropbox', 'facebook', 'github', 'google', 'linkedin', 'openidconnect', 'tumblr', 'twitter', 'windowslive', 'yahoo') else 'openidconnect-default',
                  'emailLinkingSafe': False, 
                  'options': {
                    'clientSecret': field_key['clientSecret'], 
                    'clientID': field_key['clientID'],
                  }, 
                  'type': 'oauth' if strategy in ('dropbox', 'facebook', 'github', 'google', 'linkedin', 'tumblr', 'twitter', 'windowslive', 'yahoo') else 'openidconnect',
                  'id': strategy
                }

            if 'logo_img' in field_key:
                provider_tmp = field_key['logo_img']

            providers.append(provider)

        passport_config_fn = '/etc/gluu/conf/passport-config.json'

        with open(passport_config_fn) as pcr:
            cur_config = json.load(pcr)
        
        passport_rp_client_id = self.inum2uuid(cur_config['clientId'])

        setupObject.templateRenderingDict['passport_rp_client_id'] = passport_rp_client_id
        setupObject.templateRenderingDict['passport_rp_client_cert_alias'] = cur_config['keyId']

        passport_config = self.render_template(os.path.join(self.template_dir, 'passport-config.json'))

        with open(passport_config_fn,'w') as pcw:
            pcw.write(passport_config)

        passport_central_config = self.render_template(os.path.join(self.template_dir, 'passport-central-config.json'))
        passport_central_config_js = json.loads(passport_central_config)
        passport_central_config_js['providers'] = providers
        passport_central_config = json.dumps(passport_central_config_js, indent=2)
        
        new_entry['gluuPassportConfiguration'] = [passport_central_config]

        self.write2ldif(new_dn, new_entry)

        os.system('chown -R node:node /opt/gluu/node/')
        setupObject.run_service_command('passport', 'start')

    def update_conf_files(self):

        for prop_file in ('gluu.properties', 'gluu-ldap.properties'):
            properties =  self.render_template(os.path.join(self.template_dir, prop_file))
            with open( os.path.join(setupObject.configFolder, prop_file), 'w') as w:
                w.write(properties)


    def import_ldif2ldap(self):
        print "Stopping OpenDj"
        os.system('sudo -i -u ldap "/opt/opendj/bin/stop-ds"')
        os.system('rm -f rejects.txt')
        print "Importing processed ldif"
        os.system('/opt/opendj/bin/import-ldif -b o=gluu -n userRoot -l gluu_noinum.ldif -R rejects.txt')
        print "Starting OpenDj"
        os.system('sudo -i -u ldap "/opt/opendj/bin/start-ds"')
        
    def update_shib(self):

        saml_meta_data = '/opt/shibboleth-idp/metadata/idp-metadata.xml'

        if not os.path.exists(saml_meta_data):
            return

        print "Updadting shibboleth-idp"

        print "Backing up /opt/shibboleth-idp to", self.backup_folder
        os.system('cp -r /opt/shibboleth-idp '+self.backup_folder)
        print "Updating idp-metadata.xml"
        setupObject.templateRenderingDict['idp3SigningCertificateText'] = open('/etc/certs/idp-signing.crt').read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')
        setupObject.templateRenderingDict['idp3EncryptionCertificateText'] = open('/etc/certs/idp-encryption.crt').read().replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')

        shutil.copy(saml_meta_data, self.backup_folder)

        os.chdir('/opt')
        os.system('/opt/jre/bin/jar xf {0}'.format(os.path.join(self.app_dir,'shibboleth-idp.jar')))
        os.system('rm -r /opt/META-INF')
        
        idp_tmp_dir = '/tmp/{0}'.format(str(int(time.time()*1000)))
        os.system('mkdir '+idp_tmp_dir)
        
        os.chdir(idp_tmp_dir)

        os.system('/opt/jre/bin/jar xf {0}'.format(os.path.join(self.update_dir, 'war/idp.war')))
        os.system('rm -f /opt/shibboleth-idp/webapp/WEB-INF/lib/*')
        os.system('cp -r {0}/WEB-INF/ /opt/shibboleth-idp/webapp'.format(idp_tmp_dir))

        #Recreate idp-metadata.xml with new format
        temp_fn = os.path.join(self.setup_dir, 'static/idp3/metadata/idp-metadata.xml')
        new_saml_meta_data = self.render_template(temp_fn)
        with open(saml_meta_data,'w') as f:
            f.write(new_saml_meta_data)


        for prop_fn in ('idp.properties', 'ldap.properties', 'services.properties','saml-nameid.properties'):
            print "Updating", prop_fn
            properties = self.render_template(os.path.join(self.setup_dir, 'static/idp3/conf', prop_fn))
            with open(os.path.join('/opt/shibboleth-idp/conf', prop_fn),'w') as w:
                w.write(properties)

        os.system('wget https://raw.githubusercontent.com/GluuFederation/oxTrust/master/configuration/template/shibboleth3/idp/saml-nameid.properties.vm -O /opt/gluu/jetty/identity/conf/shibboleth3/idp/saml-nameid.properties.vm')
        os.system('chown -R jetty:jetty /opt/shibboleth-idp')

        os.system('rm -r -f '+ idp_tmp_dir)

        os.chdir(cur_dir)

    def upgrade_jetty(self):

        print "Upgrading jetty"
        
        jetty_re = re.compile('jetty-distribution-(\d+).(\d+).(\d+).(.+)')

        cur_ver = glob.glob("/opt/jetty-*.*/jetty-distribution*")[0]

        rss = jetty_re.search(os.path.basename(cur_ver)).groups()
        cur_folder = '/opt/jetty-{0}.{1}'.format(rss[0], rss[1])

        print "Removing current jetty version:", cur_ver
        os.system('rm -r ' + cur_folder)
        os.system('unlink /opt/jetty')

        new_ver = max(glob.glob(os.path.join(self.update_dir, 'app/jetty-distribution*')))

        rss = jetty_re.search(os.path.basename(new_ver)).groups()
        new_folder = '/opt/jetty-{0}.{1}'.format(rss[0], rss[1])
        jetty_base_name = os.path.basename(new_ver)

        print "Installing current jetty:",jetty_base_name

        if not os.path.exists(new_folder):
            os.mkdir(new_folder)

        os.system('tar -xf {0} -C {1}'.format(new_ver, new_folder))
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

        new_folder_tmp = os.path.join(new_folder,'temp')
        
        if not os.path.exists(new_folder_tmp):
            os.mkdir(new_folder_tmp)
            
        os.system('chown -R jetty:jetty ' + new_folder)


    def update_apache_conf(self):
        
        setupObject.install_dir = setup_install_dir
        setupObject.outputFolder = os.path.join(setup_install_dir, 'output')
        setupObject.templateFolder = os.path.join(setup_install_dir, 'templates')

        setupObject.apache2_conf = os.path.join(setup_install_dir, 'output', os.path.basename(setupObject.apache2_conf))
        setupObject.apache2_ssl_conf = os.path.join(setup_install_dir, 'output', os.path.basename(setupObject.apache2_ssl_conf))
        setupObject.apache2_24_conf = os.path.join(setup_install_dir, 'output', os.path.basename(setupObject.apache2_24_conf))
        setupObject.apache2_ssl_24_conf = os.path.join(setup_install_dir, 'output', os.path.basename(setupObject.apache2_ssl_24_conf))

        apache_templates = {
                             setupObject.apache2_conf: False,
                             setupObject.apache2_ssl_conf: False,
                             setupObject.apache2_24_conf: False,
                             setupObject.apache2_ssl_24_conf: False,
                            }

        setupObject.render_templates(apache_templates)
        setupObject.configure_httpd()


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description="This script upgrades OpenDJ gluu-servers (>3.0) to 4.0")
    parser.add_argument('-o', '--online', help="online installation", action='store_true')
    argsp = parser.parse_args()

    updaterObj = GluuUpdater()
    
    if argsp.online or not os.path.exists('setup'):
        updaterObj.download_apps()

    from setup.pylib.ldif import LDIFParser, LDIFWriter
    from setup.setup import Setup
    from ldap.dn import explode_dn, str2dn

    sdb_files = []

    class MyLDIF(LDIFParser):
        def __init__(self, input_fd):
            LDIFParser.__init__(self, input_fd)
            fn = '/tmp/{}.sdb'.format(str(uuid.uuid4()))
            sdb_files.append(fn)
            self.entries = shelve.open(fn)
            self.inumOrg = None
            self.inumOrg_dn = None
            self.inumApllience = None
            self.inumApllience_dn = None
            self.idp_client = None

        def handle(self, dn, entry):
            if (dn != 'o=gluu') and (dn != 'ou=appliances,o=gluu'):
                self.entries[str(dn)] = entry
                
                if not self.inumOrg and 'gluuOrganization' in entry['objectClass']:
                    self.inumOrg_dn  = dn
                    dne = str2dn(dn)
                    self.inumOrg = dne[0][0][1]

                if not self.inumApllience and 'gluuAppliance' in entry['objectClass']:
                    self.inumApllience_dn = dn
                    dne = str2dn(dn)
                    self.inumApllience = dne[0][0][1]
                    
                if (not self.idp_client) and ('oxAuthClient' in entry['objectClass']) and (entry['displayName'][0] == 'IDP client'):
                    self.idp_client = dn

    class pureLDIFParser(LDIFParser):
        def __init__(self, input_fd):
            LDIFParser.__init__(self, input_fd)
            fn = '/tmp/{}.sdb'.format(str(uuid.uuid4()))
            sdb_files.append(fn)
            self.entries = shelve.open(fn)

        def handle(self, dn, entry):
            self.entries[str(dn)] = entry


    setup_install_dir = os.path.join(cur_dir,'setup')
    
    print "setup_install_dir", setup_install_dir
    
    setupObject = Setup(setup_install_dir)
    setupObject.load_properties('/install/community-edition-setup/setup.properties.last')
    #setupObject.load_properties('./setup.properties.last')
    setupObject.check_properties()
    setupObject.os_version = setupObject.detect_os_type()
    setupObject.calculate_selected_aplications_memory()
    setupObject.ldapCertFn = setupObject.opendj_cert_fn
    
    updaterObj.update_apache_conf()
    
    #setupObject.generate_oxtrust_api_configuration()
    #updaterObj.update_default_settings()
    #updaterObj.upgrade_jetty()
    #updaterObj.update_war()
    #updaterObj.update_passport()

    #updaterObj.dump_current_db()
    #updaterObj.update_schema()
    #updaterObj.parse_current_ldif()
    #updaterObj.process_ldif()
    #updaterObj.update_conf_files()
    #updaterObj.import_ldif2ldap()
    #updaterObj.update_shib()

    

    for sdbf in sdb_files:
        if os.path.exists(sdbf):
            os.remove(sdbf)

    #setupObject.save_properties()

    print "Please logout from container and restart Gluu Server"
    print "Notes:"
    print " * Default authentication mode was set to auth_ldap_server"
    print " * Cache provider configuration was set to 4.0 defaults"


