import sys
import StringIO
import urllib2
import ssl
import gzip
import platform
import xml.etree.ElementTree as ET
import os
import re
import zipfile
import json



newVersionAvailable = False
version = ""

os_name, os_version, os_ditro = platform.dist()

os_major = os_version.split('.')[0]

if os_name == 'redhat':
    os_name = 'rhel'

debian_release_names = {
    '9': 'stretch',
    '10': 'buster',
    '11': 'bullseye',
    }

if os_name == 'debian':
    os_ditro = debian_release_names[os_major]

os_name = os_name.lower()


def get_max_deb_version(os_name, os_ditro):

    if os_name == 'ubuntu':
        distro_path = os_ditro
        if '--testing' in sys.argv:
            distro_path += '-devel'
    else:
        distro_path = os_ditro
        if not '--testing' in sys.argv:
            distro_path += '-stable'
    
    packages_url = 'https://repo.gluu.org/{}/dists/{}/main/binary-amd64/Packages.gz'.format(os_name, distro_path)

    response = urllib2.urlopen(packages_url, context=ssl._create_unverified_context())

    strio = StringIO.StringIO(response.read())

    gzip_file = gzip.GzipFile(fileobj=strio)

    versions = []
    for l in gzip_file.readlines():
        ls = l.strip()
        if not ls:
            package_name = None

        if ls.startswith('Package:'):
            n=ls.find(':')
            pn = ls[n+1:].strip()
            if pn == 'gluu-server':
                package_name = pn
            else:
                package_name = None

        elif ls.startswith('Version:') and package_name:
            n=ls.find(':')
            vt =ls[n+1:].strip()
            vn = vt.find('-')
            v = vt[:vn]
            t = vt[vn+1:]
            versions.append((v,t))

    return max(versions)


def get_max_rpm_version(os_name, os_major):
    if '--testing' in sys.argv:
            os_major += '-testing'
    
    repodata_base_url = 'https://repo.gluu.org/{}/{}/'.format(os_name, os_major)

    response = urllib2.urlopen(os.path.join(repodata_base_url, 'repodata/repomd.xml'), context=ssl._create_unverified_context())
    root = ET.fromstring(response.read())
    ns = re.match(r'{.*}', root.tag).group(0)

    versions = ['0']

    for child in root.findall(ns+'data'):
        if child.get('type') == 'primary':
            element = child.find(ns+'location')
            primary_xml_url = os.path.join(repodata_base_url, element.get('href'))
            response = urllib2.urlopen(primary_xml_url, context=ssl._create_unverified_context())
            strio = StringIO.StringIO(response.read())
            gzip_file = gzip.GzipFile(fileobj=strio)
            primary_xml = gzip_file.read()
            
            root = ET.fromstring(primary_xml)
            ns = re.match(r'{.*}', root.tag).group(0)
            
            for child in root.findall(ns+'package'):
                name_element = child.find(ns+'name')
                package_name = name_element.text
                if package_name == 'gluu-server':
                    version_element = child.find(ns+'version')
                    ver = version_element.get('ver')
                    rel = version_element.get('rel')
                    versions.append((ver, rel))

    return max(versions)


def get_oxauth_version():
    war_zip = zipfile.ZipFile('/opt/gluu/jetty/oxauth/webapps/oxauth.war', "r")
    menifest = war_zip.read('META-INF/MANIFEST.MF')

    for l in menifest.split('\n'):
        ls = l.strip()
        if ls.startswith('Implementation-Version'):
            n = ls.find(':')
            version = ls[n+1:].strip()
            tmp_l = version.split('.')
            if tmp_l[-1].lower() in ['final']:
                version = '.'.join(tmp_l[:-1])
            return version

def get_release_version():

    with open('/etc/gluu_release') as f:
        gluu_release = f.read().strip()
    
    n = gluu_release.find('-')
    ver = gluu_release[:n]
    rel = gluu_release[n+1:]

    return (ver, rel)


try:

    if os_name in ('debian', 'ubuntu'):
        latest_repo_version = get_max_deb_version(os_name, os_ditro)

    elif os_name in ('rhel', 'centos'):
        latest_repo_version = get_max_rpm_version(os_name, os_major)

    current_version = get_release_version()

    if latest_repo_version > current_version:
        newVersionAvailable = True
        version = "{} ({})".format(latest_repo_version[0],  latest_repo_version[1])


except:
    pass

print json.dumps({"newVersionAvailable":newVersionAvailable, "version": version})
