import StringIO
import requests
import gzip
import platform
import xml.etree.ElementTree as ET
import os
import re

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

    distro_path = os_ditro if os_name == 'ubuntu' else os_ditro+'-stable'
    
    packages_url = 'https://repo.gluu.org/{}/dists/{}/main/binary-amd64/Packages.gz'.format(os_name, distro_path)

    response = requests.get(packages_url)

    strio = StringIO.StringIO(response.content)

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
            v, t = vt.split('~')
            versions.append((v,t))

    return max(versions)


def get_max_rpm_version(os_name, os_major):
    repodata_base_url = 'https://repo.gluu.org/{}/{}/'.format(os_name, os_major)
    
    result = requests.get(os.path.join(repodata_base_url, 'repodata/repomd.xml'))
    repmod_xml = result.content
    root = ET.fromstring(repmod_xml)
    ns = re.match(r'{.*}', root.tag).group(0)

    versions = ['0']

    for child in root.findall(ns+'data'):
        if child.get('type') == 'primary':
            element = child.find(ns+'location')
            primary_xml_url = os.path.join(repodata_base_url, element.get('href'))
            response = requests.get(primary_xml_url)
            strio = StringIO.StringIO(response.content)
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



if os_name in ('debian', 'ubuntu'):
    max_version = get_max_deb_version(os_name, os_ditro)

elif os_name in ('rhel', 'centos'):
    max_version = get_max_rpm_version(os_name, os_major)

print max_version
