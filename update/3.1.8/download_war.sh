ver=Final
wget -nv https://ox.gluu.org/maven/org/xdi/oxshibbolethIdp/3.1.8.$ver/oxshibbolethIdp-3.1.8.$ver.war -O war/idp.war
wget -nv https://ox.gluu.org/maven/org/xdi/oxtrust-server/3.1.8.$ver/oxtrust-server-3.1.8.$ver.war -O war/identity.war
wget -nv https://ox.gluu.org/maven/org/xdi/oxauth-server/3.1.8.$ver/oxauth-server-3.1.8.$ver.war -O war/oxauth.war
wget -nv https://ox.gluu.org/maven/org/xdi/oxShibbolethStatic/3.1.8.$ver/oxShibbolethStatic-3.1.8.$ver.jar -O app/shibboleth-idp.jar
wget -nv https://ox.gluu.org/maven/org/xdi/oxShibbolethKeyGenerator/3.1.8.$ver/oxShibbolethKeyGenerator-3.1.8.$ver.jar -O app/idp3_cml_keygenerator.jar
wget -nv https://ox.gluu.org/npm/passport/passport-3.1.8.tgz -O app/passport.tgz
wget -nv https://ox.gluu.org/npm/passport/passport-version_3.1.8-node_modules.tar.gz -O app/passport-version_3.1.8-node_modules.tar.gz
wget -nv https://repo1.maven.org/maven2/org/python/jython-installer/2.7.2/jython-installer-2.7.2.jar -O app/jython-installer-2.7.2.jar
