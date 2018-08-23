#!/usr/bin/python

import os
import sys
import time
import subprocess

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

if os.path.exists('/usr/bin/jar'):
    jar = '/usr/bin/jar'
else:
    jar = '/opt/jre/bin/jar'


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

up_dir = '/opt/upd'

backup_dir = os.path.join(up_dir, 'backup_' + time.ctime().replace(' ','_').replace(':','-'))

if not os.path.exists(backup_dir):
    os.mkdir(backup_dir)

check_list = [

    '/opt/tomcat/webapps/identity.war',
    '/opt/gluu/jetty/identity/webapps/identity.war',
    '/opt/tomcat/webapps/oxauth-rp.war',
    '/opt/gluu/jetty/oxauth-rp/webapps/oxauth-rp.war',

]


if not (os.path.exists(check_list[0]) or  os.path.exists(check_list[1])):
    sys.exit("Please be sure you are running this script inside container.")

tomcat_stopped = True

cmd = '/opt/tomcat/bin/tomcat status'
p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)



for war_file_path in check_list:

    if os.path.exists(war_file_path):

        print "Backing up", war_file_path, "to", backup_dir

        os.system('cp {0} {1}'.format(war_file_path, backup_dir))

        war_file = os.path.basename(war_file_path)
        war_path = os.path.dirname(war_file_path)

        print "Updating", war_file_path

        war_lib_dir = os.path.join(war_path, 'WEB-INF')

        if os.path.exists(war_lib_dir):
             os.system('rm -r -f {0}'.format(war_lib_dir))


        if war_file_path.startswith('/opt/tomcat/webapps'):
            cmd = '/opt/tomcat/bin/tomcat status'
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = p.communicate()
            if 'Tomcat Servlet Container is running' in output:
                tomcat_stopped = False
        
            if not tomcat_stopped:
                print "Shtting down tomcat"
                os.system('/opt/tomcat/bin/shutdown.sh')
                time.sleep(5)
                tomcat_stopped = True
                
            exploded_war_dir = war_file_path[:-4]
            war_file = os.path.basename(war_file_path)
            if os.path.exists(exploded_war_dir):
                os.system('cp -r {0} {1}'.format(exploded_war_dir, backup_dir))
                
                lib_dir = os.path.join(exploded_war_dir,'WEB-INF/lib')
            
                lib_list = os.listdir(lib_dir)
            
                for f_name in lib_list:
                    if f_name.startswith('richfaces')  and f_name.endswith('.jar'):
                        os.remove(os.path.join(lib_dir,f_name))
            
                os.system('cp -r {0} {1}'.format(os.path.join(up_dir, 'WEB-INF'), exploded_war_dir))
                os.system('chown -R tomcat:tomcat ' + exploded_war_dir)

            os.system('rm -f ' + war_file_path)
            os.chdir(exploded_war_dir)
            os.system('{0} -cf ../{1} *'.format(jar, war_file))
        else:

            os.system('cp -r {0} {1}'.format(os.path.join(up_dir, 'WEB-INF'), war_path))

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

    print

print "Please exit container and restart gluu server"
#./makeself.sh --target /opt/upd  /opt/upd  richfaces_updater.sh  "Gluu Richfaces Updater" /opt/upd/richfaces_updater.py