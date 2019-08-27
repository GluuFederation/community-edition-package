#!/usr/bin/python

import os
import glob
import subprocess
import socket

cur_dir = os.path.dirname(os.path.realpath(__file__))


def run(args):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    return output


testSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
detectedIP = [(testSocket.connect(('8.8.8.8', 80)),
               testSocket.getsockname()[0],
               testSocket.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

hostname = socket.gethostbyaddr(detectedIP)[0]
jreArchive = "amazon-corretto-8.222.10.1-linux-x64.tar.gz"

print "Hostname is detected as", hostname

print "Upgrading Java"

cacerts = []

#get host specific certs in current cacerts
cmd =['/opt/jre/bin/keytool', '-list', '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit']
result = run(cmd)
for l in result.split('\n'):
    if hostname in l:
        ls=l.split(', ')
        if ls and (hostname in ls[0]) and (not 'opendj' in l):
            alias = ls[0]
            crt_file = os.path.join(cur_dir, ls[0]+'.crt')
            run(['/opt/jre/bin/keytool', '-export', '-alias', alias, '-file', crt_file, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit'])
            cacerts.append((alias, crt_file))



print "Downloading "+ jreArchive
run(['wget', '-nv', 'https://d3pxv6yz143wms.cloudfront.net/8.222.10.1/'+jreArchive, '-O', '/tmp/'+jreArchive])

for cur_version in glob.glob('/opt/jdk*'):
    run(['rm', '-r', cur_version])

if os.path.islink('/opt/jre'):
    run(['unlink', '/opt/jre'])


print "Extracting {} into /opt/".format(jreArchive)
run(['tar', '-xzf', '/tmp/'+ jreArchive, '-C', '/opt/', '--no-xattrs', '--no-same-owner', '--no-same-permissions'])
run(['ln', '-sf', '/opt/amazon-corretto-8.222.10.1-linux-x64', '/opt/jre'])
run(['chmod', '-R', '755', '/opt/jre/bin/'])
run(['chown', '-R', 'root:root', '/opt/jre'])
run(['chown', '-h', 'root:root', '/opt/jre'])



#import certs
for alias, crt_file in cacerts:
    #ensure cert is not exists in keystore
    result = run(['/opt/jre/bin/keytool', '-list', '-alias', alias, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt'])
    if 'trustedCertEntry' in result:
        run(['/opt/jre/bin/keytool', '-delete ', '-alias', alias, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt'])

    run(['/opt/jre/bin/keytool', '-import', '-alias', alias, '-file', crt_file, '-keystore', '/opt/jre/jre/lib/security/cacerts', '-storepass', 'changeit', '-noprompt', '-trustcacerts'])

