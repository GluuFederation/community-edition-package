#!/usr/bin/python

import os
import json
import base64
import io
import re

from ldif import LDIFParser, LDIFWriter
from ldap.dn import explode_dn, str2dn, dn2str


cur_dir = os.path.dirname(os.path.realpath(__file__))

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
        self.template_dir = os.path.join(cur_dir, 'templates')
        self.scripts_ldif = os.path.join(self.template_dir, 'scripts.ldif')
        self.current_ldif_fn = os.path.join(cur_dir, 'gluu.ldif')
        self.processed_ldif_fn = os.path.join(cur_dir, 'gluu_noinum.ldif')
        self.extensionFolder = os.path.join(cur_dir, 'extension')
        self.setup_properties = parse_setup_properties()
        
    def parse_current_ldif(self):
        self.ldif_parser = MyLDIF(open(self.current_ldif_fn))
        self.ldif_parser.parse()

        self.inumOrg_ou = 'o={}'.format(self.ldif_parser.inumOrg)
        self.inumApllience_inum = 'inum={}'.format(self.ldif_parser.inumApllience)


        print "inumOrg", self.ldif_parser.inumOrg
        print "inumAppliance", self.ldif_parser.inumApllience
        print

    def prepare_scripts(self):

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

        self.scripts_parser = pureLDIFParser(ldif_io)
        self.scripts_parser.parse()
        

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

        processed_fp = open(self.processed_ldif_fn,'w')
        ldif_writer = LDIFWriter(processed_fp)

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
                oxAuthConfDynamic['clientAuthenticationFilters'][0]['baseDn'] = 'ou=clients,o=gluu'        
                new_entry['oxAuthConfDynamic'][0] = json.dumps(oxAuthConfDynamic, indent=2)

                
                oxAuthConfStatic = {
                                    "baseDn":{
                                        "configuration":"ou=configuration,o=gluu",
                                        "people":"ou=people,o=gluu",
                                        "groups":"ou=groups,o=gluu",
                                        "clients":"ou=clients,o=gluu",
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

                
                new_entry['oxTrustConfApplication'][0] = json.dumps(oxTrustConfApplication, indent=2)


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

            ldif_writer.unparse(new_dn, new_entry)

        # Add new scripts
        for scr_dn in self.scripts_parser.DNs:
            ldif_writer.unparse(scr_dn, self.scripts_parser.entries[scr_dn])


        processed_fp.close()

    def fix_ldap_properties(self):

        ox_ldap_prop_fn = '/etc/gluu/conf/ox-ldap.properties'

        ox_ldap_prop = open(ox_ldap_prop_fn).read()
        ox_ldap_prop = ox_ldap_prop.replace(self.inumApllience_inum+',ou=appliances,', '')

        with open(ox_ldap_prop_fn,'w') as w:
            w.write(ox_ldap_prop)


updaterObj = GluuUpdater()
updaterObj.parse_current_ldif()
updaterObj.prepare_scripts()
updaterObj.process_ldif()
updaterObj.fix_ldap_properties()
