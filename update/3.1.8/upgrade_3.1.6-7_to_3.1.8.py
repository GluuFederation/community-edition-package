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
import subprocess
import socket

from pyDes import *


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

    import ldap

ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)


testSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
detectedIP = [(testSocket.connect(('8.8.8.8', 80)),
               testSocket.getsockname()[0],
               testSocket.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

hostname = socket.gethostbyaddr(detectedIP)[0]
        

def get_ldap_admin_serevers_password(ox_ldap_properties_file):
    salt_file = open('/etc/gluu/conf/salt').read()
    salt = salt_file.split('=')[1].strip()
    
    
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
        elif l.startswith('bindDN'):
            binddn = l.split(':')[1].strip()
            
    return passwd, servers, binddn


class GluuUpdater:
    def __init__(self):
        
        self.gluu_app_dir = '/opt/gluu/jetty'
        self.backup_time = time.strftime('%Y-%m-%d.%H:%M:%S')
        self.update_version = '3.1.7'
        self.update_base_dir = '/opt/upd/{}-sp1-upg'.format(self.update_version)
        self.backup_folder = '{0}/backup_{1}'.format(self.update_base_dir, self.backup_time)
        self.app_dir = os.path.join(self.update_base_dir,'app')
        self.jreArchive = "amazon-corretto-8.222.10.1-linux-x64.tar.gz"
        
        for cdir in (self.app_dir, self.backup_folder):
            if not os.path.exists(cdir):
                self.logIt("Creating folder " + cdir)
                os.makedirs(cdir)

    def logIt(self, msg):
        
        with open('update.log', 'a') as w:            
            w.write('%s %s\n' % (time.strftime('%X %x'), msg))

    def backup_(self, f, keep=False):
        if os.path.exists(f):
            if keep:
                self.run(['cp','-r', '-f', f, self.backup_folder])
            else:
                self.run(['mv', f, self.backup_folder])

    def run(self, args):
        msg = 'Running ' + ' '.join(args)
        self.logIt(msg)
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
        output, err = p.communicate()
        if output:
            self.logIt(output)
        if err:
            self.logIt(err)

        return output

    def download_apps(self):

        self.run(['wget', '-nv', 'https://ox.gluu.org/maven/org/xdi/oxshibbolethIdp/{0}.Final/oxshibbolethIdp-{0}.Final.war'.format(self.update_version), '-O', os.path.join(self.app_dir, 'idp.war')])
        self.run(['wget', '-nv', 'https://ox.gluu.org/maven/org/xdi/oxtrust-server/{0}.Final/oxtrust-server-{0}.Final.war'.format(self.update_version), '-O', os.path.join(self.app_dir, 'identity.war')])
        self.run(['wget', '-nv', 'https://ox.gluu.org/maven/org/xdi/oxauth-server/{0}.Final/oxauth-server-{0}.Final.war'.format(self.update_version), '-O', os.path.join(self.app_dir, 'oxauth.war')])
        self.run(['wget', '-nv', 'https://ox.gluu.org/maven/org/xdi/oxShibbolethStatic/{0}.Final/oxShibbolethStatic-{0}.Final.jar'.format(self.update_version), '-O', os.path.join(self.app_dir, 'shibboleth-idp.jar')])
        self.run(['wget', '-nv', 'https://ox.gluu.org/npm/passport/passport-{}.tgz'.format(self.update_version), '-O', os.path.join(self.app_dir, 'passport.tgz')])
        self.run(['wget', '-nv', 'https://ox.gluu.org/npm/passport/passport-version_{}-node_modules.tar.gz'.format(self.update_version), '-O', os.path.join(self.app_dir, 'passport-node_modules.tar.gz')])
        self.run(['wget', '-nv', 'https://d3pxv6yz143wms.cloudfront.net/8.222.10.1/'+self.jreArchive, '-O', os.path.join(self.app_dir, self.jreArchive)])
        self.run(['wget', '-nv', 'https://repo1.maven.org/maven2/org/python/jython-installer/2.7.2/jython-installer-2.7.2.jar', '-O', os.path.join(self.app_dir, 'jython-installer-2.7.2.jar')])

    def updateLdapConfig(self):
        self.ldap_bind_pw, self.ldap_servers, self.ldap_bind_dn = get_ldap_admin_serevers_password('/etc/gluu/conf/ox-ldap.properties')
        ldap_host = self.ldap_servers[0]
        
        for i in range(5):
            try:
                self.conn = ldap.initialize('ldaps://{0}:1636'.format(ldap_host))
                self.conn.simple_bind_s(self.ldap_bind_dn, self.ldap_bind_pw)
                break
            except:
                print "Can't connect to LDAP Server. Retrying in 5 secs ..."
                time.sleep(5)
        else:
            sys.exit("Max retry reached. Exiting...")


        #update client uris

        result = self.conn.search_s('o=gluu', ldap.SCOPE_SUBTREE,'(&(objectClass=oxTrustConfiguration)(ou=oxtrust))', ['oxTrustConfApplication'])

        if result:
            dn = result[0][0]
            oxTrustConfApplication = json.loads(result[0][1]['oxTrustConfApplication'][0])
            oxAuthClientId = oxTrustConfApplication['oxAuthClientId']
            oxTrustConfApplication['loginRedirectUrl'] = 'https://{0}/identity/authcode.htm'.format(hostname)
            oxTrustConfApplication['logoutRedirectUrl'] = '"https://{0}/identity/finishlogout.htm'.format(hostname)
            oxTrustConfApplication_str = json.dumps(oxTrustConfApplication, indent=2)
            self.conn.modify_s(dn, [( ldap.MOD_REPLACE, 'oxTrustConfApplication',  oxTrustConfApplication_str)])

            result2 = self.conn.search_s('o=gluu', ldap.SCOPE_SUBTREE,'(&(objectClass=oxAuthClient)(inum={0}))'.format(oxAuthClientId))
            dn2 = result2[0][0]
            
            changes = [
                        ('oxAuthLogoutURI', ['https://{0}/identity/ssologout.htm'.format(hostname)]),
                        ('oxAuthRedirectURI', [
                                                'https://{0}/identity/scim/auth'.format(hostname),
                                                'https://{0}/identity/authcode.htm'.format(hostname),
                                                'https://{0}/cas/login'.format(hostname),
                                                'https://{0}/identity/ssologout.htm'.format(hostname),
                                               ]),
                        ('oxAuthPostLogoutRedirectURI', ['https://{0}/identity/finishlogout.htm'.format(hostname)]),
                    ]

            for attrib, val in changes:
                self.conn.modify_s(dn2, [( ldap.MOD_REPLACE, attrib, val)])

        else:
            sys.exit("Can't find oxTrustConfiguration. Exiting...")

    def updateWar(self):
        for app in os.listdir(self.gluu_app_dir):
            war_app = app+'.war'
            new_war_app_file = os.path.join(self.app_dir, war_app)
            if os.path.exists(new_war_app_file):
                app_dir = os.path.join(self.gluu_app_dir, app, 'webapps')
                cur_war = os.path.join(app_dir, war_app)
                if os.path.exists(cur_war):
                    print "Backing up", war_app, "to", self.backup_folder
                    self.backup_(cur_war)
                    
                print "Updating", war_app
                self.run(['cp', '-f', new_war_app_file, app_dir])


    def updateJava(self):

        print "Upgrading Java"

        cacerts = []

        #get host specific certs in current cacerts
        cmd =['/opt/jre/bin/keytool', '-list', '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit']
        result = self.run(cmd)
        for l in result.split('\n'):
            if hostname in l:
                ls=l.split(', ')
                if ls and (hostname in ls[0]) and (not 'opendj' in l):
                    alias = ls[0]
                    crt_file = os.path.join(cur_dir, ls[0]+'.crt')
                    self.run(['/opt/jre/bin/keytool', '-export', '-alias', alias, '-file', crt_file, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit'])
                    cacerts.append((alias, crt_file))


        for cur_version in glob.glob('/opt/jdk*'):
            self.run(['rm', '-r', cur_version])

        if os.path.islink('/opt/jre'):
            self.run(['unlink', '/opt/jre'])

        print "Extracting {} into /opt/".format(self.jreArchive)
        self.run(['tar', '-xzf', os.path.join(self.app_dir, self.jreArchive), '-C', '/opt/', '--no-xattrs', '--no-same-owner', '--no-same-permissions'])
        self.run(['ln', '-sf', '/opt/amazon-corretto-8.222.10.1-linux-x64', '/opt/jre'])
        self.run(['chmod', '-R', '755', '/opt/jre/bin/'])
        self.run(['chown', '-R', 'root:root', '/opt/jre'])
        self.run(['chown', '-h', 'root:root', '/opt/jre'])


        #import certs
        for alias, crt_file in cacerts:
            #ensure cert is not exists in keystore
            result = self.run(['/opt/jre/bin/keytool', '-list', '-alias', alias, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt'])
            if 'trustedCertEntry' in result:
                self.run(['/opt/jre/bin/keytool', '-delete ', '-alias', alias, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt'])

            self.run(['/opt/jre/bin/keytool', '-import', '-alias', alias, '-file', crt_file, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt', '-trustcacerts'])


    def update_jython(self):

        #check if jython is up to date
        if os.path.isdir('/opt/jython-2.7.2'):
            return

        print "Upgrading Jython"
 
        for cur_version in glob.glob('/opt/jython-2*'):
            if os.path.isdir(cur_version):
                print "Deleting", cur_version
                self.run(['rm', '-r', cur_version])

        if os.path.islink('/opt/jython'):
            self.run(['unlink', '/opt/jython'])
        
        self.run(['/opt/jre/bin/java', '-jar', os.path.join(self.app_dir, 'jython-installer-2.7.2.jar'), '-v', '-s', '-d', '/opt/jython-2.7.2', '-t', 'standard', '-e', 'ensurepip'])

        self.run(['ln', '-sf', '/opt/jython-2.7.2', '/opt/jython'])
        self.run(['chown', '-R', 'root:root', '/opt/jython-2.7.2'])
        self.run(['chown', '-h', 'root:root', '/opt/jython'])

parser = argparse.ArgumentParser(description="This script upgrades OpenDJ gluu-servers (>3.0) to 4.0")
parser.add_argument('-o', '--online', help="online installation", action='store_true')
argsp = parser.parse_args()

updaterObject = GluuUpdater()
updaterObject.download_apps()
updaterObject.update_jython()
updaterObject.updateWar()
updaterObject.updateLdapConfig()

update_java = raw_input("Do you want to replace java with {} [Y/n] ".format(updaterObject.jreArchive))

if not (update_java and update_java[0].lower() == 'n'):
    updaterObject.updateJava()

print """
Update is complete, please exit from container and restart gluu server
"""
