#!/bin/sh

UPDATE_VERSION="3.1.0.sp1"
UPD_DIR="/opt/upd/$UPDATE_VERSION/openldap/"
OPENDLDAP_SCHEMA_DIR="/opt/gluu/schema/openldap"
BACKUP_TIME=`date +%Y-%m-%d.%H:%M:%S`
BACKUP_FOLDER="/opt/upd/$UPDATE_VERSION/backup_openldap_$BACKUP_TIME"

echo "Starting the update process..."
service solderver stop

mkdir -p $BACKUP_FOLDER

if [ -f $OPENDLDAP_SCHEMA_DIR/gluu.ldif ]; then
    echo "Updating gluu.ldif...."
    mv $OPENDLDAP_SCHEMA_DIR/gluu.ldif $BACKUP_FOLDER
    cp $UPD_DIR/gluu.ldif $OPENDLDAP_SCHEMA_DIR
    chown ldap:ldap $OPENDLDAP_SCHEMA_DIR/gluu.ldif
fi

service solderver start
echo "Successfully updated"
