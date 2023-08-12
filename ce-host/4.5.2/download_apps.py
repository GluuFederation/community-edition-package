#!/usr/bin/python3

import os
import sys
import json
import zipfile
import shutil

from urllib.request import urlretrieve

cur_dir = os.path.dirname(os.path.realpath(__file__))
app_dir = os.path.join(cur_dir, 'opt/dist/app')
gluu_app_dir = os.path.join(cur_dir, 'opt/dist/gluu')

target = 'el8'
if '-el7' in sys.argv:
    target = 'el7'
elif '-el8' in sys.argv:
    target = 'el8'
elif '-el9' in sys.argv:
    target = 'el9'
elif '-ub' in sys.argv:
    target = 'ub'

app_versions = {
              "JETTY_VERSION": "9.4.35.v20201120", 
              "AMAZON_CORRETTO_VERSION": "11-x64", 
              "OX_GITVERISON": ".Final", 
              "OX_VERSION": "4.4.0", 
              "JYTHON_VERSION": "2.7.2",
              "NODE_VERSION": "v12.19.0",
              "SETUP_BRANCH": "version_4.3.0",
              "PASSPORT_NODE_VERSION": "4.3.0",
              "TWILIO_VERSION": "7.17.0",
              "JSMPP_VERSION": "2.3.7"
            }

def download(url, target_fn):
    if not target_fn.startswith('/'):
        dst = os.path.join(cur_dir, target_fn)
    else:
        dst = target_fn
    pardir, fn = os.path.split(dst)
    if not os.path.exists(pardir):
        os.makedirs(pardir)
    print("Downloading", url, "to", dst)
    urlretrieve(url, dst)

def package_oxd():
    oxd_app_dir = os.path.join(cur_dir, 'tmp')
    oxd_tgz_fn = os.path.join(oxd_app_dir, 'oxd-server.tgz')
    oxd_zip_fn = os.path.join(oxd_app_dir, 'oxd-server.zip')
    oxd_tmp_dir = os.path.join(oxd_app_dir, os.urandom(5).hex())
    download('https://ox.gluu.org/maven/org/gluu/oxd-server/{0}{1}/oxd-server-{0}{1}-distribution.zip'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), 'tmp/oxd-server.zip')
    os.mkdir(oxd_tmp_dir)
    cmd = 'unzip -qqo {} -d {}/oxd-server'.format(oxd_zip_fn, oxd_tmp_dir)
    print("Excuting", cmd)
    os.system(cmd)
    cmd = 'mkdir ' + os.path.join(oxd_tmp_dir, 'oxd-server/data')
    print("Excuting", cmd)
    os.system(cmd)
    download('https://raw.githubusercontent.com/GluuFederation/oxd/master/debian/oxd-server', os.path.join(oxd_tmp_dir, 'oxd-server/bin/oxd-server'))
    cmd = 'cd {}; tar -zcf {} oxd-server'.format(oxd_tmp_dir, oxd_tgz_fn)
    print("Excuting", cmd)
    os.system(cmd)
    os.remove(oxd_zip_fn)
    shutil.rmtree(oxd_tmp_dir)
    shutil.copyfile(os.path.join(cur_dir, 'tmp/oxd-server.tgz'), os.path.join(gluu_app_dir, 'oxd-server.tgz'))


unit_files = ['casa.service', 'idp.service', 'oxauth-rp.service', 'oxd-server.service', 'scim.service', 'fido2.service', 'identity.service', 'opendj.service', 'oxauth.service', 'passport.service']

if not '-e' in sys.argv:
    for uf in unit_files:
        base_url = 'https://raw.githubusercontent.com/GluuFederation/community-edition-package/master/package/systemd/{}'
        download(base_url.format(uf), 'etc/systemd/system/'+uf)
    
    download('https://corretto.aws/downloads/latest/amazon-corretto-{0}-linux-jdk.tar.gz'.format(app_versions['AMAZON_CORRETTO_VERSION']), os.path.join(app_dir, 'amazon-corretto-{0}-linux-jdk.tar.gz'.format(app_versions['AMAZON_CORRETTO_VERSION'])))
    download('https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/{0}/jetty-distribution-{0}.tar.gz'.format(app_versions['JETTY_VERSION']), os.path.join(app_dir, 'jetty-distribution-{0}.tar.gz'.format(app_versions['JETTY_VERSION'])))
    download('https://repo1.maven.org/maven2/org/python/jython-installer/{0}/jython-installer-{0}.jar'.format(app_versions['JYTHON_VERSION']), os.path.join(app_dir, 'jython-installer-{0}.jar'.format(app_versions['JYTHON_VERSION'])))
    download('https://nodejs.org/dist/{0}/node-{0}-linux-x64.tar.xz'.format(app_versions['NODE_VERSION']), os.path.join(app_dir, 'node-{0}-linux-x64.tar.xz'.format(app_versions['NODE_VERSION'])))
    download('https://github.com/npcole/npyscreen/archive/master.zip', os.path.join(app_dir, 'npyscreen-master.zip'))
    download('https://ox.gluu.org/maven/org/gluufederation/opendj/opendj-server-legacy/4.0.0.gluu/opendj-server-legacy-4.0.0.gluu.zip', os.path.join(app_dir, 'opendj-server-4.0.0.zip'))


    download('https://ox.gluu.org/maven/org/gluu/oxauth-server/{0}{1}/oxauth-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir, 'oxauth.war'))
    download('https://ox.gluu.org/maven/org/gluu/oxtrust-server/{0}{1}/oxtrust-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir,'identity.war'))
    download('https://ox.gluu.org/maven/org/gluu/oxauth-client/{0}{1}/oxauth-client-{0}{1}-jar-with-dependencies.jar'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir,'oxauth-client-jar-with-dependencies.jar'))
    download('https://ox.gluu.org/maven/org/gluu/oxShibbolethStatic/{0}{1}/oxShibbolethStatic-{0}{1}.jar'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir,'shibboleth-idp.jar'))
    download('https://ox.gluu.org/maven/org/gluu/oxshibbolethIdp/{0}{1}/oxshibbolethIdp-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir,'idp.war'))
    
    download('https://ox.gluu.org/npm/passport/passport-{}.tgz'.format(app_versions['OX_VERSION']), os.path.join(gluu_app_dir, 'passport.tgz'))
    download('https://ox.gluu.org/npm/passport/passport-version_{}-node_modules.tar.gz'.format(app_versions['PASSPORT_NODE_VERSION']), os.path.join(gluu_app_dir, 'passport-version_{}-node_modules.tar.gz'.format(app_versions['PASSPORT_NODE_VERSION'])))
    download('https://ox.gluu.org/maven/org/gluu/super-gluu-radius-server/{0}{1}/super-gluu-radius-server-{0}{1}.jar'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir, 'super-gluu-radius-server.jar'))
    download('https://ox.gluu.org/maven/org/gluu/super-gluu-radius-server/{0}{1}/super-gluu-radius-server-{0}{1}-distribution.zip'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir, 'gluu-radius-libs.zip'))
    
    download('https://ox.gluu.org/maven/org/gluu/casa/{0}{1}/casa-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir, 'casa.war'))
    download('https://repo1.maven.org/maven2/com/twilio/sdk/twilio/{0}/twilio-{0}.jar'.format(app_versions['TWILIO_VERSION']), os.path.join(gluu_app_dir,'twilio-{0}.jar'.format(app_versions['TWILIO_VERSION'])))
    download('https://repo1.maven.org/maven2/org/jsmpp/jsmpp/{0}/jsmpp-{0}.jar'.format(app_versions['JSMPP_VERSION']), os.path.join(gluu_app_dir, 'jsmpp-{0}.jar'.format(app_versions['JSMPP_VERSION'])))

    download('https://github.com/GluuFederation/casa/raw/version_{}/extras/casa.pub'.format(app_versions['OX_VERSION']), 'etc/certs/casa.pub')
    download('https://raw.githubusercontent.com/GluuFederation/gluu-snap/master/facter/facter', 'usr/bin/facter')
    download('https://ox.gluu.org/maven/org/gluu/scim-server/{0}{1}/scim-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir, 'scim.war'))
    download('https://ox.gluu.org/maven/org/gluu/fido2-server/{0}{1}/fido2-server-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir, 'fido2.war'))

    download('https://ox.gluu.org/maven/org/gluu/oxauth-rp/{0}{1}/oxauth-rp-{0}{1}.war'.format(app_versions['OX_VERSION'], app_versions['OX_GITVERISON']), os.path.join(gluu_app_dir, 'oxauth-rp.war'))
    download('https://github.com/GluuFederation/community-edition-setup/archive/{}.zip'.format(app_versions['SETUP_BRANCH']), os.path.join(gluu_app_dir, 'community-edition-setup.zip'))

    download('https://raw.githubusercontent.com/GluuFederation/community-edition-setup/{}/install.py'.format(app_versions['SETUP_BRANCH']), 'opt/gluu/bin/install.py')
    
    if target in ('el7', 'el8'):
        download('https://repo.gluu.org/nochroot/python-libs/py3libs-{}.tgz'.format(target), 'tmp/usr.tgz')
    
    package_oxd()

if '-x' in sys.argv:
    download('https://raw.githubusercontent.com/GluuFederation/community-edition-package/master/ce-host/4.3.0/dependencies.sh'.format(), 'opt/gluu/bin/dependencies.sh')

download('https://raw.githubusercontent.com/GluuFederation/community-edition-package/master/ce-host/4.3.0/gluu-serverd'.format(), 'usr/sbin/gluu-serverd')
download('https://raw.githubusercontent.com/GluuFederation/community-edition-package/master/ce-host/4.3.0/gluu-server.sh'.format(), 'etc/profile.d/gluu-server.sh')

for app_bin in ('usr/bin/facter', 
                'opt/gluu/bin/install.py', 
                'opt/gluu/bin/dependencies.sh', 
                'usr/sbin/gluu-serverd',
                'etc/profile.d/gluu-server.sh',
                ):
    fn = os.path.join(cur_dir, app_bin)
    if os.path.exists(fn):
        os.chmod(fn, 33261)

if target in ('el7', 'el8'):
    os.system('tar zxf {} -C {}'.format(os.path.join(cur_dir, 'tmp/usr.tgz'), cur_dir))

tmp_dir = os.path.join(cur_dir, 'tmp')
if os.path.exists(tmp_dir):
    shutil.rmtree(tmp_dir)

scripts_dir = os.path.join(cur_dir, 'opt/dist/scripts')
if not os.path.exists(scripts_dir):
    os.makedirs(scripts_dir)

open(os.path.join(scripts_dir, '.dontremove'), 'w').close()


#./makeself.sh --tar-extra "--exclude=/opt/gluu-server-4.3.0-host/download_apps.py" --target / /opt/gluu-server-4.3.0-host gluu-server-4.3.0-host.sh "Gluu CE Package 4.3.0" /opt/gluu/bin/dependencies.sh
