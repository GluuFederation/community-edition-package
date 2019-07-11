#!/usr/bin/python

import os
import json
import base64
import io
import re
import uuid

from ldif import LDIFParser, LDIFWriter
from ldap.dn import explode_dn, str2dn, dn2str

from setup.setup import Setup

cur_dir = os.path.dirname(os.path.realpath(__file__))

setupObject = Setup(os.path.join(cur_dir,'setup'))
setupObject.load_properties('/install/community-edition-setup/setup.properties.last')
setupObject.check_properties()
setupObject.generate_oxtrust_api_configuration()


class MyLDIF(LDIFParser):
    def __init__(self, input_fd):
        LDIFParser.__init__(self, input_fd)
        self.DNs = []
        self.entries = {}
        self.inumOrg = None
        self.inumOrg_dn = None
        self.inumApllience = None
        self.inumApllience_dn = None

    def handle(self, dn, entry):
        if (dn != 'o=gluu') and (dn != 'ou=appliances,o=gluu'):
            self.DNs.append(dn)
            self.entries[dn] = entry
            
            if not self.inumOrg and 'gluuOrganization' in entry['objectClass']:
                self.inumOrg_dn  = dn
                dne = str2dn(dn)
                self.inumOrg = dne[0][0][1]

            if not self.inumApllience and 'gluuAppliance' in entry['objectClass']:
                self.inumApllience_dn = dn
                dne = str2dn(dn)
                self.inumApllience = dne[0][0][1]

class pureLDIFParser(LDIFParser):
    def __init__(self, input_fd):
        LDIFParser.__init__(self, input_fd)
        self.DNs = []
        self.entries = {}

    def handle(self, dn, entry):
        self.DNs.append(dn)
        self.entries[dn] = entry



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


class GluuUpdater:
    def __init__(self):
        self.setup_dir = os.path.join(cur_dir, 'setup')
        self.template_dir = os.path.join(self.setup_dir, 'templates')
        self.scripts_ldif = os.path.join(self.template_dir, 'scripts.ldif')
        self.current_ldif_fn = os.path.join(cur_dir, 'gluu.ldif')
        self.processed_ldif_fn = os.path.join(cur_dir, 'gluu_noinum.ldif')
        self.extensionFolder = os.path.join(cur_dir, 'extension')
        self.oxtrust_api_ldif = os.path.join(self.template_dir, 'oxtrust_api.ldif')
        
    def parse_current_ldif(self):
        self.ldif_parser = MyLDIF(open(self.current_ldif_fn))
        self.ldif_parser.parse()

        self.inumOrg_ou = 'o={}'.format(self.ldif_parser.inumOrg)
        self.inumApllience_inum = 'inum={}'.format(self.ldif_parser.inumApllience)


        print "inumOrg", self.ldif_parser.inumOrg
        print "inumAppliance", self.ldif_parser.inumApllience
        print

    def add_new_scripts(self):

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


    def add_template(self, tmp_file):
        
        data_dict = setupObject.__dict__
        data_dict.update(setupObject.templateRenderingDict)
        
        ldif_temp = open(tmp_file).read()
        ldif_temp = setupObject.fomatWithDict(ldif_temp,  data_dict)
        

        ldif_io = io.StringIO(ldif_temp.decode('utf-8'))
        ldif_io.seek(0)

        parser = pureLDIFParser(ldif_io)
        parser.parse()

        for scr_dn in parser.DNs:
            self.ldif_writer.unparse(scr_dn, parser.entries[scr_dn])

        
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

        return tmps


    def process_ldif(self):

        attributes_parser = pureLDIFParser(open(os.path.join(self.template_dir, 'attributes.ldif')))
        attributes_parser.parse()

        processed_fp = open(self.processed_ldif_fn,'w')
        self.ldif_writer = LDIFWriter(processed_fp)

        for dn in self.ldif_parser.DNs:

            new_entry = self.ldif_parser.entries[dn]

            # we don't need existing scripts won't work in 4.0, passing
            if 'oxCustomScript' in new_entry['objectClass']:
                    continue

            #we won't have asimba, passing asimba related entries
            if checkIfAsimbaEntry(dn, new_entry):
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
                           

            if 'oxAuthConfDynamic' in new_entry:
                oxAuthConfDynamic = json.loads(new_entry['oxAuthConfDynamic'][0])
                oxAuthConfDynamic.pop('organizationInum')
                oxAuthConfDynamic.pop('applianceInum')        
                
                new_entry['oxAuthConfDynamic'][0] = json.dumps(oxAuthConfDynamic, indent=2)
                
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
                oxTrustConfApplication.pop('orgInum')
                oxTrustConfApplication.pop('applianceInum')

                for cli in ('scimUmaClientId', 'passportUmaClientId', 'oxAuthClientId'):
                    oxTrustConfApplication[cli] = self.inum2uuid(oxTrustConfApplication[cli])
                
                oxTrustConfApplication['applicationUrl'] = oxTrustConfApplication.pop('applianceUrl')
                oxTrustConfApplication['updateStatus'] = oxTrustConfApplication.pop('updateApplianceStatus')
                oxTrustConfApplication['loginRedirectUrl'] = 'https://%(hostname)s/identity/authcode.htm' % setupObject.__dict__
                oxTrustConfApplication['logoutRedirectUrl'] = 'https://%(hostname)s/identity/finishlogout.htm' % setupObject.__dict__


                oxTrustConfApplication['apiUmaClientId'] = '%(oxtrust_resource_server_client_id)s' % setupObject.__dict__
                oxTrustConfApplication['apiUmaClientKeyId'] = ''
                oxTrustConfApplication['apiUmaResourceId'] = '%(oxtrust_resource_id)s' % setupObject.__dict__
                oxTrustConfApplication['apiUmaScope'] = 'https://%(hostname)s/oxauth/restv1/uma/scopes/oxtrust-api-read' % setupObject.__dict__
                oxTrustConfApplication['apiUmaClientKeyStoreFile'] = '%(api_rs_client_jks_fn)s' % setupObject.__dict__
                oxTrustConfApplication['apiUmaClientKeyStorePassword'] = '%(api_rs_client_jks_pass_encoded)s' % setupObject.__dict__
                oxTrustConfApplication['oxTrustApiTestMode'] = True

                new_entry['oxTrustConfApplication'][0] = json.dumps(oxTrustConfApplication, indent=2)

            elif 'oxIDPAuthentication' in new_entry:
                oxIDPAuthentication = json.loads(new_entry['oxIDPAuthentication'][0])
                oxIDPAuthentication['config'] = json.loads(oxIDPAuthentication['config'])                
                new_entry['oxIDPAuthentication'][0] = json.dumps(oxIDPAuthentication, indent=2)


            if 'ou=configuration,o=gluu' == new_dn:
                if not 'oxCacheConfiguration' in new_entry:
                    continue

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

                if new_entry['inum'][0] == 'DF6B-4902' or new_entry['displayName'][0] == 'oxTrust Admin GUI':
                    new_entry['oxAuthLogoutURI'] = [ 'https://%(hostname)s/identity/ssologout.htm' % setupObject.__dict__ ]
                    new_entry['oxAuthRedirectURI'] = [ 'https://%(hostname)s/identity/scim/auth' % setupObject.__dict__ ,
                                                    'https://%(hostname)s/identity/authcode.htm' % setupObject.__dict__ ,
                                                    'https://%(hostname)s/oxauth/restv1/uma/gather_claims?authentication=true'  % setupObject.__dict__ ,
                                                    ]
                    new_entry['oxClaimRedirectURI'] = [ 'https://%(hostname)s/oxauth/restv1/uma/gather_claims' % setupObject.__dict__ ]
                    new_entry['oxAuthPostLogoutRedirectURI'] = [ 'https://%(hostname)s/identity/finishlogout.htm' % setupObject.__dict__ ]

                if new_entry['inum'][0] == '6D99':
                    new_entry['oxScopeType'] = ['openid']


            if 'oxPolicyScriptDn' in new_entry:
                new_entry['oxUmaPolicyScriptDn'] = [new_entry['oxPolicyScriptDn'][0]]
                new_entry.pop('oxPolicyScriptDn')
    

            if new_dn == 'ou=oxidp,ou=configuration,o=gluu':
                oxConfApplication = json.loads(new_entry['oxConfApplication'][0])
                oxConfApplication['openIdClientId'] =  self.inum2uuid(oxConfApplication['openIdClientId'])
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

            if 'oxAuthUmaScope' in new_entry:
                tmp_dn_e = explode_dn(new_entry['oxAuthUmaScope'][0])
                if 'ou=uma' in tmp_dn_e:
                    tmp_dn_e.remove('ou=uma')
                new_entry['oxAuthUmaScope'] = [ ','.join(tmp_dn_e) ]


            #Fix attributes
            if 'gluuAttribute' in new_entry['objectClass']:
                new_entry['gluuSAML1URI'] = [ 'urn:mace:dir:attribute-def:' + new_entry['gluuAttributeName'][0] ]
                new_entry['gluuSAML2URI'] = attributes_parser.entries[new_dn]['gluuSAML2URI']


            #Write modified entry to ldif
            self.ldif_writer.unparse(new_dn, new_entry)

        
        self.add_new_scripts()
        self.add_new_entries()

        self.ldif_writer.unparse('ou=resetPasswordRequests,o=gluu', {'objectClass': ['top', 'organizationalUnit'], 'ou': ['resetPasswordRequests']})
        self.ldif_writer.unparse('ou=metric,o=gluu', {'objectClass':['top','organizationalunit'], 'ou': ['metric'] })
        self.ldif_writer.unparse('ou=tokens,o=gluu', {'objectClass':['top','organizationalunit'], 'ou': ['tokens'] })
        self.ldif_writer.unparse('ou=pct,ou=uma,o=gluu', {'objectClass':['top','organizationalunit'], 'ou': ['pct'] })

        processed_fp.close()

    def fix_ldap_properties(self):

        ox_ldap_prop_fn = '/etc/gluu/conf/ox-ldap.properties'

        ox_ldap_prop = open(ox_ldap_prop_fn).read()
        ox_ldap_prop = ox_ldap_prop.replace(self.inumApllience_inum+',ou=appliances,', '')

        with open(ox_ldap_prop_fn,'w') as w:
            w.write(ox_ldap_prop)


updaterObj = GluuUpdater()
updaterObj.parse_current_ldif()
updaterObj.process_ldif()

setupObject.save_properties()

#updaterObj.fix_ldap_properties()
