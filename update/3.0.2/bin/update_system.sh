#!/bin/sh

UPDATE_VERSION="3.0.2"

# Update JVM settings
if [ -f /etc/default/oxauth ]; then
    sed -i 's/-Xmx/-XX:MaxMetaspaceSize=/g' /etc/default/oxauth
fi

if [ -f /etc/default/oxauth-rp ]; then
    sed -i 's/-Xmx/-XX:MaxMetaspaceSize=/g' /etc/default/oxauth-rp
fi

if [ -f /etc/default/identity ]; then
    sed -i 's/-Xmx/-XX:MaxMetaspaceSize=/g' /etc/default/identity
fi

if [ -f /etc/default/idp ]; then
    sed -i 's/-Xmx/-XX:MaxMetaspaceSize=/g' /etc/default/idp
fi

if [ -f /etc/default/asimba ]; then
    sed -i 's/-Xmx/-XX:MaxMetaspaceSize=/g' /etc/default/asimba
fi

if [ -f /etc/default/cas ]; then
    sed -i 's/-Xmx/-XX:MaxMetaspaceSize=/g' /etc/default/cas
fi

echo "Successfully updated"
