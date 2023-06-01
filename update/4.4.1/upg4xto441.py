#!/usr/bin/python3


import warnings
warnings.filterwarnings("ignore")
import sys

if sys.version_info.major < 3:
    print("This script runs under Python 3")
    sys.exit()

import os
import shutil
import re
import time
import json
import base64
import glob
import zipfile
import csv
import uuid
from urllib import request
import ssl
import random
import argparse
import tempfile

os.umask(0o022)

#if os.environ.get('gldev') != 'true':
#    print("This scirpt is under development. Not for use.")
#    sys.exit()

ssl._create_default_https_context = ssl._create_unverified_context
up_version = "4.4.1"
maven_base = 'https://maven.gluu.org/maven'
parser = argparse.ArgumentParser("This script upgrades gluu server 4.x to {}".format(up_version))
parser.add_argument('-d', help="Download applications and exit", action='store_true')
parser.add_argument('--offline', help="Offline upgrade", action='store_true')
parser.add_argument('-n', help="No interactive prompt before upgrade starts, 'Y' to all prompts.", action='store_true') 
parser.add_argument('-application-max-ram', help="Application max ram in MB", type=int)
parser.add_argument('-maven-user', help="Gluu Maven username", required=True)
parser.add_argument('-maven-password', help="Gluu Maven password", required=True)
argsp = parser.parse_args()

maven_base = maven_base.rstrip('/')
maven_root = '/'.join(maven_base.split('/')[:-1]).rstrip('/')
passman = request.HTTPPasswordMgrWithDefaultRealm()
passman.add_password(None, maven_root, argsp.maven_user, argsp.maven_password)
authhandler = request.HTTPBasicAuthHandler(passman)
opener = request.build_opener(authhandler)
request.install_opener(opener)


argsd = {}
argsd['n'] = argsp.n
argsd['offline'] = argsp.offline

if argsp.application_max_ram:
    argsd['application_max_ram'] = argsp.application_max_ram

installer = shutil.which('yum') if shutil.which('yum') else shutil.which('apt')

if not argsp.d and not os.path.exists('/etc/gluu/conf'):
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

try:
    from distutils import util
except:
    missing_packages.append('python3-distutils')

try:
    import pymysql
except:
    if installer.endswith('apt'):
        missing_packages.append('python3-pymysql')
    elif installer.endswith('yum') and os_version == '7':
        missing_packages.append('python36-PyMySQL')
    else:
        missing_packages.append('python3-PyMySQL')


packages = ' '.join(missing_packages)

if argsd.get('offline') and missing_packages:
    print("This script needs the following packages to continue. Please install missing packages and re-run this script.")
    print(packages)
    sys.exit()

if packages:
    print("This script requires", packages)
    cmd = installer +' install -y ' + packages
    prompt = 'y' if argsp.n else input("Install with command {}? [Y/n] ".format(cmd))
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

result = 'y' if argsp.n else input("Starting upgrade. CONTINUE? (y|N): ")

if not result.strip() or (result.strip() and result.strip().lower()[0] != 'y'):
    print("You can re-run this script to upgrade. Bye now ...")
    sys.exit()


script_replacement_prompt = ('This upgrade replaces all the default Gluu Server scripts WITH SCRIPTS FROM {}'.format(up_version),
            'and removes other custom scripts. (This will replace any customization you may',
            'have made to these default script entries) Do you want to continue? (y|N): ')
result = 'y' if argsp.n else input('\n'.join(script_replacement_prompt))

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

if not argsp.d:
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

        self.build_tag = '.Final'
        self.backup_time = time.strftime('%Y-%m-%d.%H:%M:%S')
        self.dist_folder = '/opt/upd/{}/dist'.format(up_version)

        self.ces_dir = '/install/community_edition_setup_{}'.format(up_version)

        self.dist_app_folder = os.path.join(self.dist_folder, 'app')
        self.dist_gluu_folder = os.path.join(self.dist_folder, 'gluu')
        self.dist_tmp_folder = os.path.join(self.dist_folder, 'tmp')
        self.grpcio_folder = os.path.join(self.dist_app_folder, 'grpcio')

        self.postmessages = []

        # app versions
        self.corretto_version = '11.0.14.10.1'
        self.jython_version = '2.7.3'
        self.jetty_version = '10.0.9'
        self.opendj_version = '4.4.13'
        self.node_version = 'v14.19.1'

        self.delete_from_configuration = ['gluuFreeDiskSpace', 'gluuFreeMemory', 'gluuFreeSwap', 'gluuGroupCount', 'gluuIpAddress', 'gluuPersonCount', 'gluuSystemUptime']

        self.casa_plugins = {
            'strong-authn-settings': maven_base + '/org/gluu/casa/plugins/strong-authn-settings/{0}{1}/strong-authn-settings-{0}{1}-jar-with-dependencies.jar',
            'account-linking': maven_base + '/org/gluu/casa/plugins/account-linking/{0}{1}/account-linking-{0}{1}-jar-with-dependencies.jar',
            'authorized-clients': maven_base + '/org/gluu/casa/plugins/authorized-clients/{0}{1}/authorized-clients-{0}{1}-jar-with-dependencies.jar',
            'custom-branding': maven_base + '/org/gluu/casa/plugins/custom-branding/{0}{1}/custom-branding-{0}{1}-jar-with-dependencies.jar',
            }

        self.gapp_dir = '/opt/dist/app'

    def download(self, url, target_fn):

        if os.path.exists(target_fn):
            return

        print("Downloading", url, "to", target_fn)
        for i in range(3):
            try:
                request.urlretrieve(url, target_fn)
                break
            except:
                rantom_time = random.randint(3,7)
                print("Download failed. Retry will begin in {} seconds".format(rantom_time))
                time.sleep(rantom_time)
        else:
            print("Download failed. Giving up ...")
            sys.exit()

    def download_apps(self):

        if argsp.offline:
            return

        for dist_foler in (self.dist_app_folder, self.dist_gluu_folder, self.dist_tmp_folder, self.grpcio_folder):
            if not os.path.exists(dist_foler):
                os.makedirs(dist_foler)

        downloads = [
                    (maven_base + '/org/gluu/oxtrust-server/{0}{1}/oxtrust-server-{0}{1}.war'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'identity.war')),
                    (maven_base + '/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'oxauth.war')),
                    (maven_base + '/org/gluu/fido2-server/{0}{1}/fido2-server-{0}{1}.war'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'fido2.war')),
                    (maven_base + '/org/gluu/scim-server/{0}{1}/scim-server-{0}{1}.war'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'scim.war')),
                    ('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-home/{0}/jetty-home-{0}.tar.gz'.format(self.jetty_version), os.path.join(self.dist_app_folder, 'jetty-home-{0}.tar.gz'.format(self.jetty_version))),
                    ('https://corretto.aws/downloads/resources/{0}/amazon-corretto-{0}-linux-x64.tar.gz'.format(self.corretto_version), os.path.join(self.dist_app_folder, 'amazon-corretto-{0}-linux-x64.tar.gz'.format(self.corretto_version))),
                    (maven_base + '/org/gluufederation/jython-installer/{0}/jython-installer-{0}.jar'.format(self.jython_version), os.path.join(self.dist_app_folder, 'jython-installer-{}.jar'.format(self.jython_version))),
                    ('https://nodejs.org/dist/{0}/node-{0}-linux-x64.tar.xz'.format(self.node_version), os.path.join(self.dist_app_folder, 'node-{0}-linux-x64.tar.xz'.format(self.node_version))),
                    ('https://raw.githubusercontent.com/GluuFederation/gluu-snap/master/facter/facter', os.path.join(self.dist_gluu_folder, os.path.join(self.dist_gluu_folder, 'facter'))),
                    (maven_base + '/org/gluufederation/opendj/opendj-server-legacy/{0}/opendj-server-legacy-{0}.zip'.format(self.opendj_version), os.path.join(self.dist_app_folder, 'opendj-server-{}.zip'.format(self.opendj_version))),
                    (maven_base + '/org/gluu/oxauth-client-jar-with-dependencies/{0}{1}/oxauth-client-jar-with-dependencies-{0}{1}.jar'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'oxauth-client-jar-with-dependencies.jar')),
                    ('https://github.com/GluuFederation/community-edition-setup/archive/version_{}.zip'.format(up_version), os.path.join(self.dist_gluu_folder, 'community-edition-setup.zip')),
                    ('https://ox.gluu.org/icrby8xcvbcv/spanner/gcs.tgz', os.path.join(self.dist_app_folder, 'gcs.tgz')),
                    ('https://ox.gluu.org/icrby8xcvbcv/misc/python_packages.zip', os.path.join(self.dist_app_folder, 'python_packages.zip')),
                    ('https://github.com/sqlalchemy/sqlalchemy/archive/rel_1_3_23.zip', os.path.join(self.dist_app_folder, 'sqlalchemy.zip')),
                    (maven_base + '/org/gluu/oxshibbolethIdp/{0}{1}/oxshibbolethIdp-{0}{1}.war'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'idp.war')),
                    (maven_base + '/org/gluu/oxShibbolethStatic/{0}{1}/oxShibbolethStatic-{0}{1}.jar'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'shibboleth-idp.jar')),
                    (maven_base + '/org/gluu/oxShibbolethKeyGenerator/{0}{1}/oxShibbolethKeyGenerator-{0}{1}.jar'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'idp3_cml_keygenerator.jar')),
                    ('https://raw.githubusercontent.com/GluuFederation/oxTrust/master/configuration/src/main/resources/META-INF/shibboleth3/idp/saml-nameid.properties.vm', os.path.join(self.dist_gluu_folder, 'saml-nameid.properties.vm')),
                    (maven_root + '/npm/passport/passport-{}.tgz'.format(up_version), os.path.join(self.dist_gluu_folder, 'passport.tgz')),
                    (maven_root + '/npm/passport/passport-version_{}-node_modules.tar.gz'.format(up_version), os.path.join(self.dist_gluu_folder, 'passport-version_{}-node_modules.tar.gz'.format(up_version))),
                    (maven_base + '/org/gluu/super-gluu-radius-server/{0}{1}/super-gluu-radius-server-{0}{1}-distribution.zip'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'gluu-radius-libs.zip')),
                    (maven_base + '/org/gluu/super-gluu-radius-server/{0}{1}/super-gluu-radius-server-{0}{1}.jar'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'super-gluu-radius-server.jar')),
                    (maven_base + '/org/gluu/oxd-server/{0}{1}/oxd-server-{0}{1}-distribution.zip'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'oxd-server-distribution.zip')),
                    (maven_base + '/org/gluu/casa/{0}{1}/casa-{0}{1}.war'.format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, 'casa.war')),
                    ('https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_{0}/static/casa/scripts/casa-external_smpp.py'.format(up_version), os.path.join(self.dist_gluu_folder, 'casa-external_smpp.py')),
                    ]
        for p in self.casa_plugins:
            downloads.append((self.casa_plugins[p].format(up_version, self.build_tag), os.path.join(self.dist_gluu_folder, p + '.jar')))

        downloads += [
                ('https://raw.githubusercontent.com/GluuFederation/casa/version_{}/plugins/account-linking/extras/login.xhtml'.format(up_version), os.path.join(self.dist_gluu_folder, 'login.xhtml')),
                ('https://raw.githubusercontent.com/GluuFederation/casa/version_{}/plugins/account-linking/extras/casa.py'.format(up_version), os.path.join(self.dist_gluu_folder, 'casa.py')),
                ]

        for download_link, out_file in downloads:
            self.download(download_link, out_file)


        req = request.urlopen('https://pypi.org/pypi/grpcio/1.37.0/json')
        data_s = req.read()
        data = json.loads(data_s)

        data_packages = data['releases']['1.37.0'] if 'releases' in data and '1.37.0' in data['releases'] else data['urls']

        for package in data_packages:
            ppyversion = package['python_version']
            if len(ppyversion) < 5:
                ppyversion += '0'
            if ppyversion >= 'cp350' and 'manylinux' in package['filename'] and package['filename'].endswith('manylinux2014_x86_64.whl') and package.get('url'):
                target_whl_fn = os.path.join(self.grpcio_folder, package['filename'])
                self.download(package['url'], target_whl_fn)

        if argsp.d:
            print("Download requested. Exiting ...")
            sys.exit()

    def stop_services(self):
        print("Stopping Gluu Services")
        for service in ('oxauth', 'identity', 'idp', 'oxauth-rp', 'oxd-server', 'casa', 'scim', 'fido2', 'passport'):
            if os.path.exists(os.path.join('/etc/default', service)):
                print("Stopping", service)
                self.gluuInstaller.stop(service)

        print("Cleaning Jetty cache")
        os.system('rm -r -f /opt/jetty-9.4/temp/*')


    def prepare_gcs(self):

        if not os.path.exists(os.path.join(self.gapp_dir, 'gcs')):
            print("Preparing Spanner modules")
            shutil.unpack_archive(os.path.join(self.dist_app_folder, 'gcs.tgz'), self.gapp_dir)
            pyversion = 'cp{0}{1}'.format(sys.version_info.major, sys.version_info.minor)
            for grpcio_package in glob.glob(os.path.join(self.grpcio_folder, '*.whl')):
                if grpcio_package.find(pyversion) > 0:
                    whl_zip = zipfile.ZipFile(grpcio_package)
                    for member in  whl_zip.filelist:
                        fn = os.path.basename(member.filename)
                        if fn.startswith('cygrpc.cpython') and fn.endswith('x86_64-linux-gnu.so'):
                            whl_zip.extract(member, os.path.join(self.gapp_dir, 'gcs'))
                    whl_zip.close()
                    break
            else:
                print("Can't find cygrpc.cpython module for python version", sys.version_info)
                sys.exit()

    def unzip_ces(self):
        if os.path.exists(self.ces_dir):
            return

        ces_tmp_dir = os.path.join(self.dist_tmp_folder, 'ces_{}'.format(os.urandom(4).hex()))
        #determine path
        ces_zip_fn = os.path.join(self.dist_gluu_folder, 'community-edition-setup.zip')
        ces_zip = zipfile.ZipFile(ces_zip_fn, "r")
        ces_zip_path = ces_zip.namelist()[0]

        print("Extracting CES package")
        ces_zip.extractall(ces_tmp_dir)
        extracted_path = os.path.join(ces_tmp_dir, ces_zip_path)
        shutil.copytree(extracted_path, self.ces_dir)
        shutil.rmtree(ces_tmp_dir)

        print("Extracting sqlalchemy")
        target_dir = os.path.join(self.ces_dir, 'setup_app/pylib/sqlalchemy')
        sqlalchemy_zfn = os.path.join(self.dist_app_folder, 'sqlalchemy.zip')
        sqlalchemy_zip = zipfile.ZipFile(sqlalchemy_zfn, "r")
        sqlalchemy_par_dir = sqlalchemy_zip.namelist()[0]
        tmp_dir = os.path.join(self.dist_tmp_folder, 'sqla_{}'.format(os.urandom(4).hex()))
        sqlalchemy_zip.extractall(tmp_dir)
        shutil.copytree(
                os.path.join(tmp_dir, sqlalchemy_par_dir, 'lib/sqlalchemy'), 
                target_dir
                )
        shutil.rmtree(tmp_dir)

        open(os.path.join(self.ces_dir, '__init__.py'), 'w').close()


    def prepare_ces(self):
        # we don't want to pass any argument to setup
        sys.argv = [sys.argv[0]]
        if argsd.get('n'):
            sys.argv.append('-n')

        sys.path.append(self.ces_dir)

        from setup_app.utils.arg_parser import arg_parser

        argsp = arg_parser()

        #first import paths and make changes if necassary
        from setup_app import paths

        #for example change log file location:
        #paths.LOG_FILE = '/tmp/my.log'

        from setup_app import static

        # second import module base, this makes some initial settings
        from setup_app.utils import base

        # we will access args via base module
        base.argsp = argsp

        from setup_app.utils.package_utils import packageUtils
        packageUtils.check_and_install_packages()

        from setup_app.messages import msg
        from setup_app.config import Config
        from setup_app.static import BackendTypes
        from setup_app.utils.progress import gluuProgress
        from setup_app.utils.ldif_utils import myLdifParser
        from setup_app.pylib.ldif4.ldif import LDIFWriter
        from setup_app.utils import ldif_utils
        from setup_app.setup_options import get_setup_options
        from setup_app.utils import printVersion

        from setup_app.test_data_loader import TestDataLoader
        from setup_app.utils.properties_utils import propertiesUtils
        from setup_app.utils.setup_utils import SetupUtils
        from setup_app.utils.collect_properties import CollectProperties

        from setup_app.installers.gluu import GluuInstaller
        from setup_app.installers.httpd import HttpdInstaller
        from setup_app.installers.opendj import OpenDjInstaller
        from setup_app.installers.couchbase import CouchbaseInstaller
        from setup_app.installers.jre import JreInstaller
        from setup_app.installers.jetty import JettyInstaller
        from setup_app.installers.jython import JythonInstaller
        from setup_app.installers.node import NodeInstaller
        from setup_app.installers.oxauth import OxauthInstaller
        from setup_app.installers.oxtrust import OxtrustInstaller
        from setup_app.installers.scim import ScimInstaller
        from setup_app.installers.passport import PassportInstaller
        from setup_app.installers.fido import FidoInstaller
        from setup_app.installers.saml import SamlInstaller
        from setup_app.installers.radius import RadiusInstaller
        from setup_app.installers.oxd import OxdInstaller
        from setup_app.installers.casa import CasaInstaller
        from setup_app.installers.rdbm import RDBMInstaller


        Config.gluuOptFolder
        Config.distFolder = self.dist_folder

        Config.init(paths.INSTALL_DIR)
        Config.determine_version()

        # we must initilize SetupUtils after initilizing Config
        SetupUtils.init()

        collectProperties = CollectProperties()

        if os.path.exists(Config.gluu_properties_fn):
            collectProperties.collect()
            Config.installed_instance = True

        self.base = base
        self.Config = Config
        self.passportInstaller = PassportInstaller()

        self.jreInstaller = JreInstaller()
        self.jettyInstaller = JettyInstaller()
        self.jythonInstaller = JythonInstaller()
        self.nodeInstaller = NodeInstaller()
        self.openDjInstaller = OpenDjInstaller()
        self.couchbaseInstaller = CouchbaseInstaller()
        self.rdbmInstaller = RDBMInstaller()
        self.httpdinstaller = HttpdInstaller()
        self.oxauthInstaller = OxauthInstaller()
        self.oxtrustInstaller = OxtrustInstaller()
        self.fidoInstaller = FidoInstaller()
        self.scimInstaller = ScimInstaller()
        self.samlInstaller = SamlInstaller()
        self.oxdInstaller = OxdInstaller()
        self.casaInstaller = CasaInstaller()
        self.passportInstaller = PassportInstaller()
        self.radiusInstaller = RadiusInstaller()

        for sinstaller, sinstallarg in (
                    (self.oxauthInstaller, 'installOxAuth'),
                    (self.oxtrustInstaller, 'installOxTrust'),
                    (self.fidoInstaller, 'installFido2'),
                    (self.scimInstaller, 'installScimServer'),
                    (self.samlInstaller, 'installSaml'),
                    (self.oxdInstaller, 'installOxd'),
                    (self.casaInstaller, 'installCasa'),
                    (self.passportInstaller, 'installPassport'),
                    (self.radiusInstaller, 'installGluuRadius'),
                    ):
            if getattr(sinstaller, 'installed')():
                setattr(self.Config, sinstallarg, True)


        self.rdbmInstaller.packageUtils = packageUtils
        if argsd.get('application_max_ram'):
            Config.application_max_ram = argsd['application_max_ram']
        self.jettyInstaller.calculate_selected_aplications_memory()
        self.gluuInstaller = GluuInstaller()
        self.Config.templateRenderingDict['service_user'] = self.Config.jetty_user

        self.myLdifParser = myLdifParser
        self.myLdifWriter = LDIFWriter
        self.BackendTypes = BackendTypes
        self.paths = paths
        self.base = base
        self.ldif_utils = ldif_utils

    def copy_files(self):
        self.gluuInstaller.copyFile(
                os.path.join(self.dist_gluu_folder, 'facter'),
                '/usr/bin/',
                backup=False
                )
        self.gluuInstaller.run([self.paths.cmd_chmod, '+x', '/usr/bin/facter'])
        self.gluuInstaller.copyFile(
            os.path.join(self.dist_gluu_folder, 'oxauth-client-jar-with-dependencies.jar'),
            '/opt/dist/gluu'
            )

    def prepare_persist_changes(self):
        self.persist_changes = { 
                    ('oxAuthConfDynamic', 'ou=oxauth,ou=configuration,o=gluu', 'oxAuthConfiguration'): [
                        ('tokenEndpointAuthMethodsSupported', 'add', 'element', "tls_client_auth"),
                        ('tokenEndpointAuthMethodsSupported', 'add', 'element', "self_signed_tls_client_auth"),
                        ('spontaneousScopeLifetime', 'add', 'entry', 86400),
                        ('cleanServiceInterval', 'change', 'entry',  60),
                        ('cleanServiceBatchChunkSize', 'change', 'entry',  10000),
                        ('metricReporterEnabled', 'remove', 'entry', None),
                        ('useLocalCache', 'add', 'entry', True),
                        ('backchannelAuthenticationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/bc-authorize'.format(self.Config.hostname)),
                        ('backchannelDeviceRegistrationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/bc-deviceRegistration'.format(self.Config.hostname)),
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
                        ('deviceAuthorizationEndpoint', 'add', 'entry', 'https://{}/oxauth/restv1/device-authorization'.format(self.Config.hostname)),
                        ('grantTypesSupported', 'add', 'element', 'urn:ietf:params:oauth:grant-type:device_code'),
                        ('dynamicGrantTypeDefault', 'add', 'element', 'urn:ietf:params:oauth:grant-type:device_code'),
                        ('deviceAuthzRequestExpiresIn', 'add', 'entry', 1800),
                        ('deviceAuthzTokenPollInterval', 'add', 'entry', 5),
                        ('deviceAuthzResponseTypeToProcessAuthz', 'add', 'entry', 'code'),
                    ],
    
                    ('oxAuthConfStatic', 'ou=oxauth,ou=configuration,o=gluu', 'oxAuthConfiguration'): [
                        ('baseDn', 'change', 'subentry', ('sessions', 'ou=sessions,o=gluu')),
                        ('baseDn', 'change', 'subentry', ('ciba', 'ou=ciba,o=gluu')),
                    ],
    
                    ('oxTrustConfApplication', 'ou=oxtrust,ou=configuration,o=gluu', 'oxTrustConfiguration'): [
                        ('useLocalCache', 'add', 'entry', True),
                        ('loggingLayout', 'add', 'entry', 'text'),
                        ('caCertsLocation', 'change', 'entry', self.Config.default_trust_store_fn),
                        ('caCertsPassphrase', 'change', 'entry', self.Config.defaultTrustStorePW),
                    ],
                    
                    ('oxConfApplication', 'ou=oxidp,ou=configuration,o=gluu', 'oxApplicationConfiguration'): [
                        ('scriptDn', 'add', 'entry', 'ou=scripts,o=gluu'),
                    ],

                    ('oxTrustConfCacheRefresh', 'ou=oxtrust,ou=configuration,o=gluu', 'oxTrustConfiguration'): [
                        ('inumConfig', 'change', 'subentry', ('bindDN', self.Config.ldap_binddn)),
                    ],

                }
    def generate_smtp_keystore(self):
        if os.path.exists(self.Config.smtp_jks_fn):
            return

        print("Generating smtp keystore")
        if not self.Config.get('smtp_jks_pass'):
            self.Config.smtp_jks_pass = self.gluuInstaller.getPW()
            self.Config.smtp_jks_pass_enc = self.gluuInstaller.obscure(self.Config.smtp_jks_pass)

        self.gluuInstaller.service_name = 'gluu'
        self.gluuInstaller.generate_configuration()
        self.persist_changes[('oxSmtpConfiguration', 'ou=configuration,o=gluu', 'gluuConfiguration')] = [
                                        ('connectProtectionList', 'add', 'entry', ['None','StartTls','SslTls']),
                                        ('key-store', 'add', 'entry', self.Config.smtp_jks_fn),
                                        ('key-store-password', 'add', 'entry', self.Config.smtp_jks_pass_enc),
                                        ('key-store-alias', 'add', 'entry', self.Config.smtp_alias),
                                        ('signing-algorithm', 'add', 'entry', self.Config.smtp_signing_alg),
                                    ]

        self.gluuInstaller.chown(self.Config.smtp_jks_fn, 'root', self.Config.gluu_user)
        self.gluuInstaller.run([self.paths.cmd_chmod, '660', self.Config.smtp_jks_fn])

    def fix_gluu_config(self):
        print("Fixing Gluu configuration files")
        with open(self.Config.gluu_properties_fn) as f:
            gluu_prop = f.readlines()

        for l in gluu_prop:
            if l.startswith('fido2_ConfigurationEntryDN'):
                break
        else:
            for i, l in enumerate(gluu_prop[:]):
                if l.strip().startswith('oxradius_ConfigurationEntryDN'):
                    gluu_prop.insert(i+1, 'fido2_ConfigurationEntryDN=ou=fido2,ou=configuration,o=gluu\n')
                    break

            self.gluuInstaller.writeFile(self.Config.gluu_properties_fn, ''.join(gluu_prop))

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

                    options += ' -Dpython.home=' + self.Config.jython_home
                    idp_default[i] = 'JAVA_OPTIONS="{}"\n'.format(options)
                    self.gluuInstaller.writeFile(idp_default_fn, ''.join(idp_default))

        passport_default_fn = '/etc/default/passport'
        if os.path.exists(passport_default_fn):
            self.Config.templateRenderingDict['node_base'] = self.nodeInstaller.node_base
            passport_default = self.render_template(os.path.join(self.ces_dir, 'templates/node/passport'))
            self.gluuInstaller.writeFile(passport_default_fn, passport_default)


    def update_persistence_data(self):

        if self.gluuInstaller.dbUtils.moddb == self.BackendTypes.LDAP:
           self.update_ldap()
        elif self.gluuInstaller.dbUtils.moddb == self.BackendTypes.COUCHBASE:
           self.update_couchbase()

        for config_element, config_dn, object_class in self.persist_changes:
            print("Updating", config_element)
            
            if self.gluuInstaller.dbUtils.get_backend_location_for_dn(config_dn) == self.BackendTypes.COUCHBASE:
                key = self.ldif_utils.get_key_from(config_dn)
                bucket = self.gluuInstaller.dbUtils.get_bucket_for_key(key)
                n1ql = 'SELECT {} from `{}` WHERE `objectClass`="{}" AND `dn`="{}"'.format(config_element, bucket, object_class, config_dn)
                n1ql_result = self.gluuInstaller.dbUtils.cbm.exec_query(n1ql)
                result = n1ql_result.json().get('results', [{}])[0]
            else:
                ldap_filter = '(&({0}=*)(objectClass={1}))'.format(config_element, object_class)
                result = self.gluuInstaller.dbUtils.search(config_dn, search_filter=ldap_filter, search_scope=ldap3.BASE)

            if not result:
                if config_element != 'oxSmtpConfiguration':
                    continue
                result = {}

            cur_data = result.get(config_element, {})

            if isinstance(cur_data, list):
                cur_data = cur_data[0]

            js_conf = json.loads(cur_data) if isinstance(cur_data, str) else cur_data

            if config_element == 'oxSmtpConfiguration':
                ssl = js_conf.pop('requires-ssl', None)
                if ssl:
                    js_conf['connect-protection'] = 'StartTls'
                if 'connect-protection' in js_conf:
                    js_conf['connect-protection'] = js_conf['connect-protection'].replace('SSL_TLS', 'SslTls').replace('START_TLS', 'StartTls').replace('NONE','None')
                js_conf.pop('connectProtectionList', None)

            self.apply_persist_changes(js_conf, self.persist_changes[(config_element, config_dn, object_class)])

            if self.gluuInstaller.dbUtils.get_backend_location_for_dn(config_dn) != self.BackendTypes.COUCHBASE:
                new_conf = json.dumps(js_conf, indent=2)
            else:
                new_conf = js_conf

            self.gluuInstaller.dbUtils.set_configuration(config_element, new_conf, dn=config_dn)


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

    def drop_index(self, bucket, index_name):
        cmd = 'DROP INDEX `{}`.`{}` USING GSI'.format(bucket, index_name)
        print("Removing index", index_name)
        self.gluuInstaller.dbUtils.cbm.exec_query(cmd)

    def add_index(self, bucket, ind):
        cmd, index_name = self.couchbaseInstaller.couchbaseMakeIndex(bucket, ind)
        if 'defer_build' in cmd:
            if not bucket in self.new_cb_indexes:
                self.new_cb_indexes[bucket] = []
            self.new_cb_indexes[bucket].append(index_name)
        print("Executing", cmd)
        self.gluuInstaller.dbUtils.cbm.exec_query(cmd)

    def cb_indexes(self):
        print("Updating Couchbase indexes")

        self.new_cb_indexes = {}
        new_index_json_fn = os.path.join(self.ces_dir, 'static/couchbase/index.json')
        new_index_json_s = self.gluuInstaller.readFile(new_index_json_fn)
        new_index_json_s = new_index_json_s.replace('!bucket_prefix!', self.Config.couchbase_bucket_prefix)
        new_indexes = json.loads(new_index_json_s)

        data_result = self.gluuInstaller.dbUtils.cbm.exec_query('SELECT * FROM system:indexes')
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

        for bucket in self.Config.couchbaseBuckets:
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
            self.gluuInstaller.dbUtils.cbm.exec_query(cmd)

    def get_existing_buckets(self):
        existing_buckets = []
        r = self.gluuInstaller.dbUtils.cbm.get_buckets()

        if r.ok:
            b_ = r.json()
            existing_buckets = [ bucket['name'] for bucket in b_ ]

        return existing_buckets

    def update_couchbase(self):

        if self.Config.couchbase_bucket_prefix+'_token' in self.Config.couchbaseBuckets:
            session_bucket = self.Config.couchbase_bucket_prefix + '_session'
            self.Config.couchbaseBuckets.append(session_bucket)
            self.Config.mappingLocations['session'] = 'couchbase'
            
            #add missing buckets:
            existing_buckets = self.get_existing_buckets()

            if not session_bucket in  existing_buckets:
                bcr = self.gluuInstaller.dbUtils.cbm.add_bucket(session_bucket, self.Config.couchbaseBucketDict['session']['memory_allocation'])
                
                if not bcr.ok:
                    print("Failed to create bucket {}, reason: {}".format(session_bucket, bcr.text))
                    print("Please solve the issue. Exiting for now.")
                    sys.exit()
                else:
                    print("Bucket {} created".format(session_bucket))
                    self.postmessages.append("Please use couchbase administrator panel and adjust Memory Quota for bucket {}".format(session_bucket))

            #check if bucket is ready for five times
            for i in range(5):
                time.sleep(random.randint(1,3))
                existing_buckets = self.get_existing_buckets()
                if session_bucket in existing_buckets:
                    break

            # get all sessions from gluu_token, add sid if not exists and move to gluu_session
            result = self.gluuInstaller.dbUtils.cbm.exec_query('SELECT META().id FROM `{}_token` WHERE exp > "" and objectClass = "oxAuthSessionId"'.format(self.Config.couchbase_bucket_prefix))

            if result.ok:
                data = result.json()
                for d in data.get('results',[]):
                    docid = d['id']
                    #remove session entry:
                    self.gluuInstaller.dbUtils.cbm.exec_query('DELETE FROM `{}_token` USE KEYS "{}"'.format(self.Config.couchbase_bucket_prefix, docid))

        self.couchbaseInstaller.couchbaseProperties()

        self.cb_indexes()



    def apply_persist_changes(self, js_conf, data):
        for key, change_type, how_change, value in data:
            if key not in js_conf and change_type != 'add':
                    continue
            if change_type == 'add':
                if how_change == 'entry' or key not in js_conf:
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

        self.gluuInstaller.dbUtils.ldap_conn.search(
                    search_base=dn, 
                    search_scope=ldap3.BASE,
                    search_filter='(objectclass=*)',
                    attributes=self.delete_from_configuration
                    )

        result = self.gluuInstaller.dbUtils.ldap_conn.response
        if result:
            for k in result[0]['attributes']:
                if result[0]['attributes'][k]:
                        self.gluuInstaller.dbUtils.ldap_conn.modify(
                        dn, 
                        {k: [ldap3.MODIFY_DELETE, result[0]['attributes'][k]]}
                        )

        # we need to delete index oxAuthExpiration before restarting opendj
        oxAuthExpiration_index_dn = 'ds-cfg-attribute=oxAuthExpiration,cn=Index,ds-cfg-backend-id=userRoot,cn=Backends,cn=config'
        self.gluuInstaller.dbUtils.ldap_conn.search(
            search_base=oxAuthExpiration_index_dn, 
            search_scope=ldap3.BASE, 
            search_filter='(objectclass=*)', 
            attributes=['ds-cfg-attribute']
            )

        if self.gluuInstaller.dbUtils.ldap_conn.response:
            self.gluuInstaller.dbUtils.ldap_conn.delete(oxAuthExpiration_index_dn)

        self.gluuInstaller.dbUtils.ldap_conn.unbind()

        print("Updating Gluu OpenDJ schema files")

        self.openDjInstaller.prepare_opendj_schema()
        time.sleep(5)

        # rebind opendj
        self.gluuInstaller.dbUtils.ldap_conn.bind()


        # add oxDocumentStoreConfiguration if not exists
        self.gluuInstaller.dbUtils.ldap_conn.search(search_base=dn, search_scope=ldap3.BASE, search_filter='(objectclass=*)', attributes=["oxDocumentStoreConfiguration"])
        result = self.gluuInstaller.dbUtils.ldap_conn.response
        if not result or not result[0]['raw_attributes'].get('oxDocumentStoreConfiguration'):
            self.gluuInstaller.dbUtils.ldap_conn.modify(
                        dn, 
                        {'oxDocumentStoreConfiguration': [ldap3.MODIFY_ADD, '{"documentStoreType":"LOCAL","localConfiguration":{"baseLocation":"/"},"jcaConfiguration":{"serverUrl":"http://localhost:8080/rmi","workspaceName":"default","connectionTimeout":15,"userId":"admin","password":""},"webDavConfiguration":null}']}
                        )

        dn = 'ou=sessions,o=gluu'
        self.gluuInstaller.dbUtils.ldap_conn.search(
                    search_base=dn, 
                    search_scope=ldap3.SUBTREE, 
                    search_filter='(objectClass=*)', 
                    attributes=['*']
                    )
        if self.gluuInstaller.dbUtils.ldap_conn.response:
            for session_entry in self.gluuInstaller.dbUtils.ldap_conn.response:
                #? delete or modify?
                #self.conn.delete(session_entry['dn'])
                if ('oxAuthSessionId' in session_entry['attributes']['objectClass']) and (not 'sid' in session_entry['attributes']):
                    self.gluuInstaller.dbUtils.ldap_conn.modify(
                                session_entry['dn'], 
                                {'sid': [ldap3.MODIFY_ADD, str(uuid.uuid4())]}
                                )
        else:
            print("Adding sessions base entry")
            self.gluuInstaller.dbUtils.ldap_conn.add(dn, attributes={'objectClass': ['top', 'organizationalUnit'], 'ou': ['sessions']})




    def update_opendj(self):
        build_fn = '/opt/opendj/config/buildinfo'
        if not os.path.exists(build_fn):
            # opendj was not installed on this server
            return

        # check if opendj needs to be updated
        opendj_fn = os.path.join(self.dist_app_folder, 'opendj-server-{}.zip'.format(self.opendj_version))
        opendj_zip = zipfile.ZipFile(opendj_fn)
        latest_build = opendj_zip.read('opendj/template/config/buildinfo').decode()
        with open('/opt/opendj/config/buildinfo') as f:
            cur_build = f.read()
        if latest_build == cur_build:
            print("OpenDJ is up to date.")
            return

        # unbind opendj
        try:
            self.gluuInstaller.dbUtils.ldap_conn.unbind()
        except:
            pass

        print("Updating OpenDJ")
        print("Stopping OpenDJ")
        self.gluuInstaller.stop('opendj')
        print("Extracting OpenDJ")
        opendj_zip.extractall('/opt')
        opendj_zip.close()
        print("Executing OpenDJ upgrade script")
        self.gluuInstaller.run([os.path.join(self.Config.ldapBaseFolder, 'upgrade'), '-n'])
        self.gluuInstaller.run(['chown', '-R', 'ldap:ldap', self.Config.ldapBaseFolder])
        print("Starting OpenDJ")
        self.gluuInstaller.start('opendj')

        # rebind opendj
        self.gluuInstaller.dbUtils.ldap_conn.bind()

    def update_java(self):
        
        if os.path.isdir('/opt/amazon-corretto-{}-linux-x64'.format(self.corretto_version)):
            print("Java is up to date")
            return

        print ("Upgrading Java")

        cacerts = []

        print("Extracting current cacerts")
        #get host specific certs in current cacerts
        cmd =[self.Config.cmd_keytool, '-list', '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit']
        result = self.gluuInstaller.run(cmd)
        for l in result.split('\n'):
            if self.Config.hostname in l:
                ls = l.split(', ')
                if ls and (self.Config.hostname in ls[0]) and (not 'opendj' in l):
                    alias = ls[0]
                    crt_file = os.path.join(cur_dir, ls[0]+'.crt')
                    self.gluuInstaller.run(['/opt/jre/bin/keytool', '-export', '-alias', alias, '-file', crt_file, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit'])
                    cacerts.append((alias, crt_file))
 
        for cur_version in glob.glob('/opt/amazon-corretto*'):
            if os.path.isdir(cur_version):
                print("Deleting", cur_version)
                self.gluuInstaller.run(['rm', '-r', '-f', cur_version])

        if os.path.islink('/opt/jre'):
            self.gluuInstaller.run(['unlink', '/opt/jre'])

        print("Installing Java")
        self.jreInstaller.start_installation()

        print("Importing cacerts")
        #import certs
        for alias, crt_file in cacerts:
            #ensure cert is not exists in keystore
            result = self.gluuInstaller.run(['/opt/jre/bin/keytool', '-list', '-alias', alias, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt'])
            if 'trustedCertEntry' in result:
                self.gluuInstaller.run(['/opt/jre/bin/keytool', '-delete ', '-alias', alias, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt'])

            self.gluuInstaller.run(['/opt/jre/bin/keytool', '-import', '-alias', alias, '-file', crt_file, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt', '-trustcacerts'])

    def update_jython(self):

        #check if jython is up to date
        if os.path.isdir('/opt/jython-{}'.format(self.jython_version)):
            print("Jython is up to date")
            return
        print ("Upgrading Jython")

        for cur_version in glob.glob('/opt/jython-2*'):
            if os.path.isdir(cur_version):
                print("Deleting", cur_version)
                self.gluuInstaller.run(['rm', '-r', '-f', cur_version])

        if os.path.islink('/opt/jython'):
            self.gluuInstaller.run(['unlink', '/opt/jython'])

        print("Installing Jython", self.jython_version)
        self.jythonInstaller.start_installation()


    def update_node(self):

        #check if jython is up to date
        if os.path.isdir('/opt/node-{}-linux-x64'.format(self.node_version)):
            print("Node is up to date")
            return

        print("Upgrading Node")

        for cur_version in glob.glob('/opt/node-v*'):
            if os.path.isdir(cur_version):
                print("Deleting", cur_version)
                self.gluuInstaller.run(['rm', '-r', cur_version])

        if os.path.islink('/opt/node'):
            self.gluuInstaller.run(['unlink', '/opt/node'])

        print("Installing Node", self.node_version)
        self.nodeInstaller.start_installation()


    def update_war_files(self):
        gluu_app_dir = '/opt/dist/gluu'
        if not os.path.exists(gluu_app_dir):
            os.makedirs(gluu_app_dir)

        cur_dist_dir = self.Config.distFolder

        for service in self.jettyInstaller.jetty_app_configuration:
            service_webapps_dir = os.path.join(self.Config.jetty_base, service)
            if os.path.exists(service_webapps_dir):
                backup_dir = service_webapps_dir+'.'+time.ctime().replace(' ', '_')
                print("Backing up to", backup_dir)
                self.gluuInstaller.run(['mv', service_webapps_dir, backup_dir])
                print("Updating Gluu jetty deployment for {}.war".format(service))

                src_war_fn = os.path.join(self.dist_gluu_folder, service+'.war')

                self.Config.distFolder = '/opt/dist'
                self.jettyInstaller.source_files=[[src_war_fn, None]]
                self.jettyInstaller.service_name = service
                self.jettyInstaller.installJettyService(self.jettyInstaller.jetty_app_configuration[service], True)
                self.Config.distFolder = cur_dist_dir

                #let's also copy these files into /opt/dist/gluu
                self.gluuInstaller.copyFile(
                            src_war_fn,
                            gluu_app_dir,
                            backup=False
                            )

                for copy_dir in ('conf', 'custom', 'plugins'):
                    src_dir = os.path.join(backup_dir, copy_dir)
                    if os.path.exists(src_dir):
                        self.gluuInstaller.run(['cp', '-r', src_dir, service_webapps_dir])

    def update_jetty(self):
        # delete old Jetty distribution
        for jdist in glob.glob(os.path.join(self.gapp_dir, 'jetty-distribution-9.4*')):
            os.remove(jdist)

        # copy new Jetty distribution to 

        src_jdist = os.path.join(self.dist_app_folder, 'jetty-home-{0}.tar.gz'.format(self.jetty_version))

        self.gluuInstaller.copyFile(
                            src_jdist,
                            self.gapp_dir,
                            backup=False
                            )

        if os.path.isdir('/opt/jetty-10.0/jetty-home-{}'.format(self.jetty_version)):
            print("Jetty is up to date")
            return

        print("Upgrading Jetty")

        for cur_version in glob.glob('/opt/jetty-*'):
            if os.path.isdir(cur_version):
                print("Deleting", cur_version)
                self.gluuInstaller.run(['rm', '-r', cur_version])

        if os.path.islink('/opt/jetty'):
            self.gluuInstaller.run(['unlink', '/opt/jetty'])

        print("Installing Jetty", self.jetty_version)
        self.jettyInstaller.start_installation()


    def update_scripts(self):
        print("Updating Scripts")

        self.gluuInstaller.determine_key_gen_path()
        self.Config.enable_scim_access_policy = 'true' if self.passportInstaller.installed() else 'false'

        #we need dummy password for oxtrust_admin_password if not exists
        if not self.Config.oxtrust_admin_password:
            self.Config.oxtrust_admin_password = self.gluuInstaller.getPW()

        self.oxtrustInstaller.generate_configuration()

        self.gluuInstaller.prepare_base64_extension_scripts()

        self.gluuInstaller.renderTemplate(self.oxtrustInstaller.ldif_scripts)

        ldif_scripts_fn = os.path.join(self.Config.outputFolder, os.path.basename(self.oxtrustInstaller.ldif_scripts))
        self.passportInstaller.logIt("Parsing", ldif_scripts_fn)
        print("Parsing", ldif_scripts_fn)

        parser = self.myLdifParser(ldif_scripts_fn)
        parser.parse()

        if self.casaInstaller.installed():
            print("Rendering Casa scripts")
            self.casaInstaller.render_import_templates(import_script=False)
            self.gluuInstaller.renderTemplate(self.casaInstaller.ldif_scripts)
            self.gluuInstaller.logIt("Parsing", self.casaInstaller.ldif_scripts)
            print("Parsing", self.casaInstaller.ldif_scripts)
            casa_scripts_parser = self.myLdifParser(self.casaInstaller.ldif_scripts)
            casa_scripts_parser.parse()
            for e in casa_scripts_parser.entries:
                print("Adding casa script", e[0])
                parser.entries.append(e)

        if self.passportInstaller.installed():
            print("Rendering Passport scripts")
            self.Config.passport_rp_client_jks_fn = self.passportInstaller.passport_rp_client_jks_fn
            self.Config.passport_rp_client_jks_pass = 'secret'

            scripts_template = os.path.join(self.passportInstaller.passport_templates_folder, os.path.basename(self.passportInstaller.ldif_scripts_fn))
            extensions = self.base.find_script_names(scripts_template)
            self.passportInstaller.prepare_base64_extension_scripts(extensions=extensions)
            self.passportInstaller.renderTemplateInOut(self.passportInstaller.ldif_scripts_fn, self.passportInstaller.passport_templates_folder, os.path.join(self.Config.outputFolder,'passport'))

            self.gluuInstaller.logIt("Parsing", self.passportInstaller.ldif_scripts_fn)
            print("Parsing", self.passportInstaller.ldif_scripts_fn)
            passport_scripts_parser = self.myLdifParser(self.passportInstaller.ldif_scripts_fn)
            passport_scripts_parser.parse()
            for e in passport_scripts_parser.entries:
                print("Adding passport script", e[0])
                parser.entries.append(e)

        new_scripts = []

        for dn, entry in parser.entries:
            if self.gluuInstaller.dbUtils.dn_exists(dn):
                print("Updating script", dn)
                self.gluuInstaller.dbUtils.set_configuration('oxScript', entry['oxScript'][0], dn=dn)
            else:
                new_scripts.append((dn, entry))

        if new_scripts:
            self.unparse_import(new_scripts)

    def update_apache_conf(self):
        print("Updating Apache Configuration")
        self.httpdinstaller.write_httpd_config()

    def render_template(self, tmp_file):

        jetty_info = self.jettyInstaller.get_jetty_info()

        self.Config.templateRenderingDict['jetty_dist'] = jetty_info[1]

        data_dict = self.gluuInstaller.merge_dicts(self.Config.templateRenderingDict, self.Config.__dict__)
        data_dict.update(self.Config.templateRenderingDict)
        
        temp = self.gluuInstaller.readFile(tmp_file)
        temp = self.gluuInstaller.fomatWithDict(temp,  data_dict)
        
        return temp

    def update_shib(self):

        if not self.samlInstaller.installed():
            return

        print("Updadting shibboleth-idp")

        saml_meta_data_fn = os.path.join(self.samlInstaller.idp3Folder, 'metadata', self.samlInstaller.idp3_metadata)
        shib_backup_dir = self.samlInstaller.idp3Folder + '.back-' + self.backup_time

        print("Backing up to", shib_backup_dir)
        
        self.samlInstaller.copyTree(self.samlInstaller.idp3Folder, shib_backup_dir)
        print("Unpacking shibboleth-idp.jar")

        self.samlInstaller.unpack_idp3()
        
        print("Updating idp-metadata.xml")
        self.Config.templateRenderingDict['idp3SigningCertificateText'] = self.samlInstaller.readFile('/etc/certs/idp-signing.crt').replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')
        self.Config.templateRenderingDict['idp3EncryptionCertificateText'] = self.samlInstaller.readFile('/etc/certs/idp-encryption.crt').replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','')

        self.samlInstaller.backupFile(saml_meta_data_fn)

        #Recreate idp-metadata.xml with new format
        temp_fn = os.path.join(self.ces_dir, 'static/idp3/metadata/idp-metadata.xml')
        new_saml_meta_data = self.render_template(temp_fn)
        self.samlInstaller.writeFile(saml_meta_data_fn, new_saml_meta_data)

        for prop_fn in ('idp.properties', 'ldap.properties', 'services.properties','saml-nameid.properties'):
            print("Updating", prop_fn)
            properties = self.render_template(os.path.join(self.ces_dir, 'static/idp3/conf', prop_fn))
            self.samlInstaller.writeFile(os.path.join('/opt/shibboleth-idp/conf', prop_fn), properties)

        self.samlInstaller.copyFile(
                    os.path.join(self.dist_gluu_folder, 'saml-nameid.properties.vm'), 
                    '/opt/gluu/jetty/identity/conf/shibboleth3/idp/',
                    backup=False
                    )
        self.samlInstaller.run(['chown', '-R', 'jetty:jetty', '/opt/shibboleth-idp'])

    def update_radius(self):

        radius_dir = self.radiusInstaller.radius_dir
        radius_libs_dir = os.path.join(radius_dir, 'libs')

        if not os.path.exists(radius_dir):
            return

        print("Updating Gluu Radius Server")

        self.gluuInstaller.copyFile(
                os.path.join(self.ces_dir, 'static/radius/etc/init.d/gluu-radius'),
                '/etc/init.d',
                backup=False
                )

        self.gluuInstaller.run(['chmod', '+x', '/etc/init.d/gluu-radius'])

        backup_folder = radius_libs_dir + '_' + self.backup_time

        self.gluuInstaller.run(['mv', radius_libs_dir, backup_folder])

        radius_libs = os.path.join(self.dist_gluu_folder, 'gluu-radius-libs.zip')
        radius_jar = os.path.join(self.dist_gluu_folder, 'super-gluu-radius-server.jar')

        self.gluuInstaller.run(['unzip', '-o', '-q', radius_libs, '-d', radius_dir ])
        self.gluuInstaller.copyFile(radius_jar, radius_dir, backup=False)

        self.gluuInstaller.copyFile(
                    os.path.join(self.ces_dir, 'static/radius/etc/default/gluu-radius'),
                    self.Config.osDefault,
                    backup=False
                    )


    def update_oxd(self):
        if not self.oxdInstaller.installed():
            return

        sys.path.append(os.path.join(self.dist_app_folder, 'python_packages.zip'))
        import sqlparse

        tmp_dir = tempfile.mkdtemp()
        db_backup_fn = os.path.join(tmp_dir, 'backup.sql')
        db_modidifed_script = os.path.join(tmp_dir, 'import.sql')

        self.oxdInstaller.stop()

        cmd = '{0} -cp {1}/lib/oxd-server.jar org.h2.tools.Script -url jdbc:h2:file:{1}/data/oxd_db -user oxd -password oxd -script {2}'.format(self.Config.cmd_java, self.oxdInstaller.oxd_root, db_backup_fn)
        self.oxdInstaller.run(cmd, shell=True)

        print("Updating oxd Server")
        for f in glob.glob(os.path.join(self.oxdInstaller.oxd_root, 'lib/*')):
            if os.path.isfile(f):
                self.oxdInstaller.logIt("Removing " + f)
                os.remove(f)

        oxd_zip_fn = os.path.join(self.dist_gluu_folder, 'oxd-server-distribution.zip')
        oxd_zip = zipfile.ZipFile(oxd_zip_fn)
        for member in  oxd_zip.filelist:
            if member.filename.startswith('lib/') and not member.is_dir():
                self.oxdInstaller.logIt("Extracting {} from {} to {}".format(member.filename, oxd_zip_fn, self.oxdInstaller.oxd_root))
                oxd_zip.extract(member, self.oxdInstaller.oxd_root)

        oxd_yaml = self.oxdInstaller.get_yaml_config()

        if self.casaInstaller.installed() and hasattr(self, 'casa_oxd_host') and getattr(self, 'casa_oxd_host') in (self.Config.hostname, self.Config.ip):

            write_oxd_yaml = False
            if 'bind_ip_addresses' in oxd_yaml:
                if not self.Config.ip in oxd_yaml['bind_ip_addresses']:
                    oxd_yaml['bind_ip_addresses'].append(self.Config.ip)
                    write_oxd_yaml = True
            else:
                for i, k in enumerate(oxd_yaml):
                    if k == 'storage':
                        break
                else:
                    i = 1
                oxd_yaml.insert(i, 'bind_ip_addresses',  [self.Config.ip])
                write_oxd_yaml = True

            if write_oxd_yaml:
                yml_str = ruamel.yaml.dump(oxd_yaml, Dumper=ruamel.yaml.RoundTripDumper)
                self.oxdInstaller.writeFile(self.oxdInstaller.oxd_server_yml_fn, yml_str)


            #create oxd certificate if not CN=hostname
            r = os.popen('/opt/jre/bin/keytool -list -v -keystore {}  -storepass {} | grep Owner'.format(oxd_yaml['server']['applicationConnectors'][0]['keyStorePath'], oxd_yaml['server']['applicationConnectors'][0]['keyStorePassword'])).read()
            for l in r.splitlines():
                res = re.search('CN=(.*?.),', l)
                if res:
                    cert_cn = res.groups()[0]
                    if cert_cn != self.Config.hostname:
                        self.oxdInstaller.run([
                            self.paths.cmd_openssl,
                            'req', '-x509', '-newkey', 'rsa:4096', '-nodes',
                            '-out', os.path.join(self.dist_tmp_folder, 'oxd.crt'),
                            '-keyout', os.path.join(self.dist_tmp_folder, 'oxd.key'),
                            '-days', '3650',
                            '-subj', '/C={}/ST={}/L={}/O={}/CN={}/emailAddress={}'.format(self.Config.countryCode, self.Config.state, self.Config.city, self.Config.orgName, self.Config.hostname, self.Config.admin_email),
                            ])

                        self.oxdInstaller.run([
                            self.paths.cmd_openssl,
                            'pkcs12', '-export',
                            '-in', os.path.join(self.dist_tmp_folder, 'oxd.crt'),
                            '-inkey', os.path.join(self.dist_tmp_folder, 'oxd.key'),
                            '-out', os.path.join(self.dist_tmp_folder, 'oxd.p12'),
                            '-name', self.Config.hostname,
                            '-passout', 'pass:example'
                            ])

                        self.oxdInstaller.run([
                            self.Config.cmd_keytool,
                            '-importkeystore',
                            '-deststorepass', 'example',
                            '-destkeypass', 'example',
                            '-destkeystore', os.path.join(self.dist_tmp_folder, 'oxd.keystore'),
                            '-srckeystore', os.path.join(self.dist_tmp_folder, 'oxd.p12'),
                            '-srcstoretype', 'PKCS12',
                            '-srcstorepass', 'example',
                            '-alias', self.Config.hostname,
                            ])

                        self.oxdInstaller.backupFile(oxd_yaml['server']['applicationConnectors'][0]['keyStorePath'])
                        self.oxdInstaller.copyFile(
                                os.path.join(self.dist_tmp_folder, 'oxd.keystore'),
                                oxd_yaml['server']['applicationConnectors'][0]['keyStorePath'],
                                backup=False
                                )
                        self.oxdInstaller.run(['chown', 'jetty:jetty', oxd_yaml['server']['applicationConnectors'][0]['keyStorePath']])

                        for f in ('oxd.crt', 'oxd.key', 'oxd.p12', 'oxd.keystore'):
                            fp = os.path.join(self.dist_tmp_folder, f)
                            self.oxdInstaller.run(['rm', '-f', f])


        print("Updating /etc/default/oxd-server")
        default_fn = os.path.join('/etc/default/oxd-server')
        default_tmp = os.path.join(self.ces_dir, 'static/oxd/oxd-server.default')
        default_ = self.render_template(default_tmp)
        self.gluuInstaller.writeFile(default_fn, default_)

        backup_text = self.oxdInstaller.readFile(db_backup_fn)

        cleaned_text = []

        for l in backup_text.splitlines():
            if not l.startswith((';','--')):
                cleaned_text.append(l)

        statements = sqlparse.split('\n'.join(cleaned_text))

        with open(db_modidifed_script, 'w') as w:
            for statement in statements:
                if statement.upper().strip().startswith('INSERT INTO PUBLIC.RP'):
                    w.write(statement + '\n')


        for db_fn in glob.glob('{}/data/oxd_db*.db'.format(self.oxdInstaller.oxd_root)):
            os.remove(db_fn)

        self.oxdInstaller.start()
        time.sleep(5)
        self.oxdInstaller.stop()
        cmd = '{0} -cp {1}/lib/oxd*.jar org.h2.tools.RunScript -url jdbc:h2:file:{1}/data/oxd_db -user oxd -password oxd -script {2}'.format(self.Config.cmd_java, self.oxdInstaller.oxd_root, db_modidifed_script)
        self.oxdInstaller.run(cmd, shell=True)

        shutil.rmtree(tmp_dir)

        print("Restarting oxd-server")
        
        self.oxdInstaller.start()
        time.sleep(5)


        if self.Config.get('oxd_server_https'):
            print("Importing oxd certificate to cacerts")
            self.oxdInstaller.import_oxd_certificate()


    def update_casa(self):

        if not self.casaInstaller.installed():
            return

        print("Updating casa")
        casa_config_dn = 'ou=casa,ou=configuration,o=gluu'
        casa_config_json = {}
        casa_cors_domains_fn = os.path.join(self.casaInstaller.casa_jetty_dir, 'casa-cors-domains')
        casa_config_json_fn = os.path.join(self.Config.configFolder, 'casa.json')

        if os.path.exists(casa_config_json_fn):
            casa_config_json_s = self.casaInstaller.readFile(casa_config_json_fn)
            casa_config_json = json.loads(casa_config_json_s)

            if os.path.exists(casa_cors_domains_fn):
                casa_cors_domains = self.casaInstaller.readFile(casa_cors_domains_fn)
                casa_cors_domains_list = [l.strip() for l in casa_cors_domains.splitlines()]
                casa_config_json['allowed_cors_domains'] = casa_cors_domains_list

        casa_plugins_dir = os.path.join(self.casaInstaller.casa_jetty_dir, 'plugins')
        self.casaInstaller.run_service_command('casa', 'stop')

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
                        jar_fn = os.path.join(self.dist_gluu_folder, pid + '.jar')
                        self.casaInstaller.run(['rm', '-f', plugin])
                        self.casaInstaller.copyFile(jar_fn, casa_plugins_dir, backup=False)
                    if pid == 'account-linking':
                        account_linking = True

        if os.path.exists(casa_plugins_dir):
             self.gluuInstaller.chown(casa_plugins_dir, self.Config.gluu_user, self.Config.gluu_user, recursive=True)
             self.gluuInstaller.run([self.paths.cmd_chmod, '644', casa_plugins_dir])

        if account_linking:
            self.casaInstaller.copyFile(
                    os.path.join(self.dist_gluu_folder, 'login.xhtml'),
                    os.path.join(self.Config.jetty_base, 'oxauth/custom/pages'),
                    backup=False
                    )

            scr = self.casaInstaller.readFile(os.path.join(self.dist_gluu_folder, 'casa.py'))

            al_dn = 'inum=BABA-CACA,ou=scripts,o=gluu'

            self.casaInstaller.dbUtils.set_configuration('oxScript', scr, dn=al_dn)

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
            print("Updating database for casa")
            if self.casaInstaller.dbUtils.dn_exists(casa_config_dn):
                self.casaInstaller.dbUtils.set_configuration('oxConfApplication', casa_config_json_s, dn=casa_config_dn)
            else:
                entry = {'objectClass': ['top', 'oxApplicationConfiguration'], 'ou': ['casa'], 'oxConfApplication': [casa_config_json_s]}
                self.unparse_import([(casa_config_dn, entry)])

            self.casaInstaller.backupFile(casa_config_json_fn)

        pylib_dir = os.path.join(self.Config.gluuOptPythonFolder, 'libs')
        libdir_base_url = 'https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_{}/static/casa/scripts'.format(up_version)
        for casa_lib in glob.glob(os.path.join(pylib_dir, 'casa-external*.py')):
            casa_lib_fn = os.path.basename(casa_lib)
            try:
                response = request.urlopen(os.path.join('https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_{}/static/casa/scripts'.format(up_version), casa_lib_fn))
                if response.code == 200:
                    self.casaInstaller.backupFile(casa_lib)
                    print ("Updating", casa_lib)
                    target_fn = os.path.join(pylib_dir, casa_lib_fn)
                    scr = response.read()
                    print ("Writing", target_fn)
                    with open(target_fn, 'wb') as w: 
                        w.write(scr)
            except Exception as e:
                print ("ERROR Updating", casa_lib_fn)
                self.casaInstaller.logIt("ERROR Updating " + casa_lib_fn, True)
                self.casaInstaller.logIt(str(e), True)


        data = self.casaInstaller.dbUtils.dn_exists(casa_config_dn)
        if data:
            casa_conf = data['oxConfApplication'][0] if isinstance(data['oxConfApplication'], list) else data['oxConfApplication']
            oxConfApplication = json.loads(casa_conf) if isinstance(casa_conf, str) else casa_conf
        else:
            oxConfApplication = json.load(open('/etc/gluu/conf/casa.json'))

        if not oxConfApplication.get('oxd_config'):
            oxConfApplication['oxd_config'] = {}
            
        oxConfApplication['oxd_config']['authz_redirect_uri'] = 'https://{}/casa'.format(self.Config.hostname)
        oxConfApplication['oxd_config']['frontchannel_logout_uri'] = 'https://{}/casa/autologout'.format(self.Config.hostname)
        oxConfApplication['oxd_config']['post_logout_uri'] = 'https://{}/casa/bye.zul'.format(self.Config.hostname)

        if not oxConfApplication['oxd_config'].get('port'):
            oxConfApplication['oxd_config']['port'] = 8443
        if not oxConfApplication['oxd_config'].get('host'):
            oxConfApplication['oxd_config']['host'] = self.Config.get('oxd_hostname', self.Config.hostname)
            self.casa_oxd_host = oxConfApplication['oxd_config']['host']

        if not 'protocol' in oxConfApplication['oxd_config']:
            oxConfApplication['oxd_config']['protocol'] = 'https'

        if oxConfApplication.get('plugins_settings', {}).get('strong-authn-settings', {}).get('basic_2fa_settings'):
            oxConfApplication['plugins_settings']['strong-authn-settings']['basic_2fa_settings']['allowSelectPreferred'] = False

        if data:
            self.casaInstaller.dbUtils.set_configuration('oxConfApplication', json.dumps(oxConfApplication, indent=2), casa_config_dn)
        else:
            entry = {'objectClass': ['top', 'oxApplicationConfiguration'], 'ou': ['casa'], 'oxConfApplication': [json.dumps(oxConfApplication, indent=2)]}
            self.unparse_import([('ou=casa,ou=configuration,o=gluu', entry)])

        self.Config.oxd_server_https = 'https://{}:{}'.format(oxConfApplication['oxd_config']['host'], oxConfApplication['oxd_config']['port'])

    def update_passport(self):
        if not self.passportInstaller.installed():
            return

        print("Updating Passport Configuration")
        data = self.passportInstaller.dbUtils.dn_exists('ou=oxpassport,ou=configuration,o=gluu')

        if data and 'gluuPassportConfiguration' in data:
            passport_config = data['gluuPassportConfiguration'][0] if isinstance(data['gluuPassportConfiguration'], list) else data['gluuPassportConfiguration']
            js_data = json.loads(passport_config) if isinstance(passport_config, str) else passport_config

            if 'providers' in js_data:

                for provider in js_data['providers']:

                    if provider.get('type') == 'openidconnect':
                        print("Updating passport provider {}".format(provider.get('displayName')))
                        data_changes = (('type', 'openid-client'), ('mapping','openid-client'), ('passportStrategyId', 'openid-client'))
                        for k,v in data_changes:
                            if k in provider:
                                provider[k] = v

                        for k in ('userInfoURL', 'tokenURL', 'authorizationURL'):
                            if k in provider.get('options', {}):
                                del provider['options'][k]


                        for ko,kn in (('clientID', 'client_id'), ('clientSecret', 'client_secret')):
                            if ko in provider.get('options', {}):
                                provider['options'][kn] = provider['options'].pop(ko)

                        provider['options']['token_endpoint_auth_method'] = 'client_secret_post'

            self.passportInstaller.dbUtils.set_configuration('gluuPassportConfiguration', json.dumps(js_data), dn='ou=oxpassport,ou=configuration,o=gluu')

        backup_folder = self.passportInstaller.gluu_passport_base + '_' + self.backup_time
        print("Stopping passport server")
        self.passportInstaller.stop()
        print("Updating Passport")

        self.passportInstaller.create_folders()
        self.passportInstaller.extract_passport()
        self.passportInstaller.extract_modules()

        # copy mappings
        for m_path in glob.glob(os.path.join(backup_folder, 'server/mappings/*.js')):
            with open(m_path) as f:
                fc = f.read()
                if re.search('profile["[\s\S]*"]', fc):
                    mfn = os.path.basename(m_path)
                    if not os.path.exists(os.path.join(self.passportInstaller.gluu_passport_base, 'server/mappings', mfn)):
                        self.passportInstaller.copyFile(
                            m_path,
                            os.path.join(self.passportInstaller.gluu_passport_base, 'server/mappings'),
                            backup=False
                            )

        self.passportInstaller.run([self.paths.cmd_chown, '-R', 'node:gluu', self.passportInstaller.gluu_passport_base])


    def add_oxAuthUserId_pairwiseIdentifier(self):
        data = self.gluuInstaller.dbUtils.search('ou=people,o=gluu', search_filter='(objectClass=pairwiseIdentifier)', search_scope=ldap3.SUBTREE, fetchmany=True)
        if data:
            print("Adding oxAuthUserId to pairwiseIdentifier.")
            print("This may take several minutes depending on your user number")
            total_number = len(data)
            for i, pdata in enumerate(data):
                entry = pdata[1]
                print("Processing {} of {} : {}".format(i+1, total_number, entry['dn']))
                if not 'oxAuthUserId' in entry:
                    for dne in dnutils.parse_dn(entry['dn']):
                            if dne[0] == 'inum':
                                oxAuthUserId =  dne[1]
                                self.gluuInstaller.dbUtils.set_configuration('oxAuthUserId', oxAuthUserId, entry['dn'])
                                break

    def fix_fido2(self):

        if not self.fidoInstaller.installed():
            return

        print("Updating Fido2 Configuration")
        self.fidoInstaller.render_import_templates(do_import=False)
        fido2_config_dn = 'ou=fido2,ou=configuration,o=gluu'

        if self.fidoInstaller.dbUtils.dn_exists(fido2_config_dn):
            gluuConfDynamic = self.fidoInstaller.readFile(self.fidoInstaller.fido2_dynamic_conf_json)
            self.fidoInstaller.dbUtils.set_configuration('gluuConfDynamic', gluuConfDynamic, dn=fido2_config_dn)
        else:
            self.fidoInstaller.dbUtils.import_ldif([self.fidoInstaller.ldif_fido2])

        data = self.gluuInstaller.dbUtils.search('ou=people,o=gluu', search_filter='(objectClass=oxDeviceRegistration)', search_scope=ldap3.SUBTREE, fetchmany=True)
        if data:
            print("Adding personInum to oxDeviceRegistration")
            print("This may take several minutes depending on your user number")
            total_number = len(data)
            for i, pdata in enumerate(data):
                entry = pdata[1]
                print("Processing {} of {} : {}".format(i+1, total_number, entry['dn']))
                if not 'personInum' in entry:
                    for dne in dnutils.parse_dn(entry['dn']):
                            if dne[0] == 'inum':
                                oxAuthUserId =  dne[1]
                                self.gluuInstaller.dbUtils.set_configuration('personInum', oxAuthUserId, entry['dn'])
                                break


        toc_jwt_fn = os.path.join(self.Config.configFolder, 'fido2/mds/toc/toc.jwt')
        self.base.download('https://mds.fidoalliance.org/', toc_jwt_fn)
        self.gluuInstaller.chown(toc_jwt_fn, self.Config.root_user, self.Config.gluu_group)

        root_r3_fn = os.path.join(self.Config.configFolder, 'fido2/mds/cert/root-r3.crt')
        self.base.download('https://secure.globalsign.com/cacert/root-r3.crt', root_r3_fn)
        self.gluuInstaller.chown(root_r3_fn, self.Config.root_user, self.Config.gluu_group)

    def update_attributes(self):

        attributes_ldif_fn = os.path.join(self.ces_dir, 'templates/attributes.ldif')
        attributes_ldif = self.myLdifParser(attributes_ldif_fn)
        attributes_ldif.parse()

        dn = 'inum=6049,ou=attributes,o=gluu'

        attribue_6049 = self.gluuInstaller.dbUtils.dn_exists(dn)
        if attribue_6049:
            perms = attribue_6049.get('oxAuthClaimName', [])
            if isinstance(perms, str):
                perms = [perms]
            if not 'user_permission' in perms:
                print("Modifying attribute", dn)
                perms.append('user_permission')
                self.gluuInstaller.dbUtils.set_configuration('oxAuthClaimName', perms, dn)

        new_attributes = []

        for dn, entry in attributes_ldif.entries:
            if not self.gluuInstaller.dbUtils.dn_exists(dn):
                new_attributes.append((dn, entry))

        if new_attributes:
            print("Updating attributes")
            self.unparse_import(new_attributes)


    def unparse_import(self, entries):
        ldif_fn = os.path.join(self.dist_tmp_folder, 'gluu_updater_{}.ldif'.format(os.urandom(4).hex()))
        with open(ldif_fn, 'wb') as w:
            ldif_writer = self.myLdifWriter(w, cols=1000)
            for dn, endtry in entries:
                print("Preparing", dn)
                ldif_writer.unparse(dn, endtry)
        print("Writing {} to database".format(dn))
        self.gluuInstaller.dbUtils.import_ldif([ldif_fn])
        os.remove(ldif_fn)


    def update_scopes(self):

        ldif_fn = os.path.join(self.ces_dir, 'templates/scopes.ldif')
        ldif_parser = self.myLdifParser(ldif_fn)
        ldif_parser.parse()

        new_scopes = []

        for dn, entry in ldif_parser.entries:
            u = self.gluuInstaller.dbUtils.dn_exists(dn)
            if not self.gluuInstaller.dbUtils.dn_exists(dn):
                new_scopes.append((dn, entry))

        if new_scopes:
            print("Updating scopes")
            self.unparse_import(new_scopes)

    def update_default_settings(self):
        print("Updating /etc/default files")
        for service in ('casa', 'fido2', 'identity', 'idp', 'oxauth', 'scim'):
            default_fn = os.path.join('/etc/default', service)
            print("Updating default file", service)
            if os.path.exists(default_fn):
                default_ = self.render_template(os.path.join(self.ces_dir, 'templates/jetty', service))
                self.gluuInstaller.writeFile(default_fn, default_)

updaterObj = GluuUpdater()


updaterObj.download_apps()
updaterObj.prepare_gcs()
updaterObj.unzip_ces()

updaterObj.prepare_ces()
updaterObj.copy_files()
updaterObj.prepare_persist_changes()
updaterObj.generate_smtp_keystore()

updaterObj.update_default_settings()
updaterObj.stop_services()
updaterObj.update_java()
updaterObj.update_opendj()
updaterObj.update_jython()

updaterObj.update_jetty()

updaterObj.update_node()
updaterObj.update_scopes()
updaterObj.update_attributes()
updaterObj.fix_gluu_config()
updaterObj.update_persistence_data()

updaterObj.update_war_files()

updaterObj.update_scripts()
updaterObj.update_apache_conf()
updaterObj.update_passport()
updaterObj.update_radius()
updaterObj.update_casa()
updaterObj.update_oxd()
sys.exit()
updaterObj.add_oxAuthUserId_pairwiseIdentifier()
updaterObj.fix_fido2()
updaterObj.update_shib()

os.system('systemctl daemon-reload')

print()
for msg in updaterObj.postmessages:
    print("*", msg)
print()
print("Please logout from container and restart Gluu Server")

#./makeself.sh --target /opt/upd/4.4.1 /opt/upd/4.4.1 4-4-0.rc1-upg.run "Gluu Server 4.x to 4.4.1 Upgrader Script" /opt/upd/4.4.1/upg4xto440.py --offline
