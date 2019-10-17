mkdir -p war
mkdir -p app

version=4.0.Final

wget -nv https://raw.githubusercontent.com/GluuFederation/community-edition-package/master/update/4.0/update.py -O update.py
wget -nv https://ox.gluu.org/maven/org/gluu/oxshibbolethIdp/$version/oxshibbolethIdp-$version.war -O war/idp.war
wget -nv https://ox.gluu.org/maven/org/gluu/oxtrust-server/$version/oxtrust-server-$version.war -O war/identity.war
wget -nv https://ox.gluu.org/maven/org/gluu/oxauth-server/$version/oxauth-server-$version.war -O war/oxauth.war
wget -nv https://ox.gluu.org/maven/org/gluu/oxShibbolethStatic/$version/oxShibbolethStatic-$version.jar -O war/shibboleth-idp.jar
wget -nv https://ox.gluu.org/maven/org/gluu/oxShibbolethKeyGenerator/$version/oxShibbolethKeyGenerator-$version.jar -O war/idp3_cml_keygenerator.jar
wget -nv https://ox.gluu.org/npm/passport/passport-4.0.0.tgz -O app/passport.tgz
wget -nv https://ox.gluu.org/npm/passport/passport-version_4.0-node_modules.tar.gz -O app/passport-node_modules.tar.gz
wget -nv https://d3pxv6yz143wms.cloudfront.net/8.222.10.1/amazon-corretto-8.222.10.1-linux-x64.tar.gz -O app/amazon-corretto-8.222.10.1-linux-x64.tar.gz
wget -nv https://ox.gluu.org/maven/org/forgerock/opendj/opendj-server-legacy/4.0.0-M3/opendj-server-legacy-4.0.0-M3.zip -O app/opendj-server-legacy-4.0.0-M3.zip
wget -nv https://nodejs.org/dist/v12.6.0/node-v12.6.0-linux-x64.tar.xz -O app/node-v12.6.0-linux-x64.tar.xz
wget -nv https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/9.4.19.v20190610/jetty-distribution-9.4.19.v20190610.tar.gz -O app/jetty-distribution-9.4.19.v20190610.tar.gz
wget -nv https://raw.githubusercontent.com/GluuFederation/oxTrust/master/configuration/src/main/resources/META-INF/shibboleth3/idp/saml-nameid.properties.vm -O app/saml-nameid.properties.vm
wget -nv https://raw.githubusercontent.com/GluuFederation/community-edition-package/master/update/4.0/update_casa.py -O update_casa.py


if [ ! -f "jsonmerge" ] 
then
    wget -nv https://github.com/avian2/jsonmerge/archive/master.zip -O /tmp/jsonmerge-master.zip
    unzip -qo /tmp/jsonmerge-master.zip -d /tmp
    cp -r /tmp/jsonmerge-master/jsonmerge ./
fi


if [ ! -f "setup" ] 
then
    rm -r -f setup
fi

wget -nv https://github.com/GluuFederation/community-edition-setup/archive/master.zip -O /tmp/community-edition-setup-master.zip
unzip -qo /tmp/community-edition-setup-master.zip -d /tmp
mv /tmp/community-edition-setup-master ./setup
touch setup/__init__.py

chmod +x update.py
chmod +x update_casa.py

