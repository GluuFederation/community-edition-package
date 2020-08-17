# Upgrade CE-3.1.x with Remote LDAP

Download and run upgrade script inside 3.1.x Gluu Server Container

```
mkdir upg4.0
cd upg4.0
wget https://raw.githubusercontent.com/GluuFederation/community-edition-package/master/update/4.0/testing/remote/update_remote_ldap.py
python update_remote_ldap.py -o --remote-ldap
```

Upgrade script will download all necessary components and upgrade them. Once it prompts the following 
(note `hostname` and `rootUserPassword` will be different for your server)

```
Use the following setup.ptoperties on server to install WrenDS as explained here:
https://github.com/GluuFederation/community-edition-package/tree/master/update/4.0/testing/remote/README.md
######## setup.properties begins ###########
hostname                        =c1.gluu.org
rootUserPassword                =TopSecretPassword
ldapPort                        =389
generateSelfSignedCertificate   =true
enableStartTLS                  =false
ldapsPort                       =1636
adminConnectorPort              =4444
rootUserDN                      =cn=directory manager
baseDN                          =o=gluu
backendType                     =je
######## setup.properties ends ###########
```

Login to your remote ldap server. Backup and remove ldap server. Here I assume that you
are using opendj installed at `/opt/opendj`.

```
/opt/opendj/bin/stop-ds
mv /opt/opendj/ /opt/opendj.back
```

Download WrenDS and extract:

```
wget -nv https://ox.gluu.org/maven/org/forgerock/opendj/opendj-server-legacy/4.0.0-M3/opendj-server-legacy-4.0.0-M3.zip -O /opt/opendj-server-legacy-4.0.0-M3.zip
cd /opt
unzip opendj-server-legacy-4.0.0-M3.zip
```

Download CE-4.0 schema files:

```
wget https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_4.0/static/opendj/101-ox.ldif -O /opt/opendj/template/config/schema/101-ox.ldif
wget https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_4.0/static/opendj/77-customAttributes.ldif -O /opt/opendj/template/config/schema/77-customAttributes.ldif
wget https://raw.githubusercontent.com/GluuFederation/community-edition-setup/version_4.0/static/opendj/96-eduperson.ldif -O /opt/opendj/template/config/schema/96-eduperson.ldif

```

If you have custom schema files copy those schema files to `/opt/opendj/template/config/schema/`
or if you modified gluu schema files, it is time to apply the changes.

Now write content of `/opt/opendj/setup.properties` as follows 
(note `hostname` and `rootUserPassword` will be different for your server):

```
hostname                        =c1.gluu.org
rootUserPassword                =TopSecretPassword
ldapPort                        =389
generateSelfSignedCertificate   =true
enableStartTLS                  =false
ldapsPort                       =1636
adminConnectorPort              =4444
rootUserDN                      =cn=directory manager
baseDN                          =o=gluu
backendType                     =je
```

Execute setup as


```
cd /opt/opendj
./setup --cli --propertiesFilePath /opt/opendj/setup.properties --acceptLicense --no-prompt
```

Once WrenDS setup completed, you can turn to your CE-3.1.x server and hit **&lt;ENTER&gt;** key to continue
