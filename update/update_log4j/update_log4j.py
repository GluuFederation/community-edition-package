from __future__ import print_function
import zipfile
import os
import shutil
import glob

cur_dir = os.path.dirname(os.path.realpath(__file__))
exe_dir = os.getcwd()
os.chdir(cur_dir)
jarfn_dict = {}

for jfn in glob.glob(os.path.join(cur_dir, 'jar/*.jar')):
    n = jfn.rfind('-')
    jarfn_dict[os.path.basename(jfn[:n])] = jfn


def update_war(target_fn):
    print("Updating", target_fn)
    war_zip = zipfile.ZipFile(target_fn)
    modified = False
    for member in  war_zip.filelist:
        fn = os.path.basename(member.filename)
        for jf in jarfn_dict:
            if fn.startswith(jf):
                modified = True
                log4j_fn = jarfn_dict[jf]
                print("Removing {} form {}".format(member.filename, target_fn))
                dirn = os.path.dirname(member.filename)
                cmd_rf = 'zip -dq {} {}'.format(target_fn, member.filename)
                os.system(cmd_rf)
                if not os.path.exists(dirn):
                    os.makedirs(dirn)
                shutil.copy(log4j_fn, dirn)
                add_fn = os.path.join(dirn, os.path.basename(log4j_fn))
                print("Adding {} to {}".format(add_fn, target_fn))
                cmd_af = '/opt/jre/bin/jar vfu {} {}'.format(target_fn, add_fn)
                os.system(cmd_af)
    if modified:
        print("Chowning {} to jetty".format(target_fn))
        os.system('chown jetty:jetty {}'.format(target_fn))

if os.path.exists('/etc/gluu/conf'):
    dist = 'gluu'
elif os.path.exists('/etc/jans/conf'):
    dist = 'jans'
else:
    print("No Gluu/Janssen installation was found")
    sys.exit()

for fn in glob.glob('/opt/{}/jetty/*/webapps/*.war'.format(dist)):
    update_war(fn)

shib_dir = '/opt/shibboleth-idp/webapp/WEB-INF/lib'
if os.path.exists(shib_dir):
    print("Updating Shibboleth libs")
    for jf in jarfn_dict:
        fl = glob.glob(os.path.join(shib_dir, jf+'*.jar'))
        if fl:
            print("Deleting", fl[0])
            os.remove(fl[0])
            print("Copying", jarfn_dict[jf], "to", shib_dir)
            shutil.copy(jarfn_dict[jf], shib_dir)

os.chdir(exe_dir)

print("\033[93mPlease logout from container and restart {} server\033[0m".format(dist.title()))

#./makeself.sh --target /opt/upd/update_log4j  /opt/upd/update_log4j update_log4j.run  "Gluu log4j updater" /opt/upd/update_log4j/start.sh

