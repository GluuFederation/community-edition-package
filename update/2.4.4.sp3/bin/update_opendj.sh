#!/bin/sh

UPDATE_VERSION="2.4.4.sp3"
UPD_DIR="/opt/upd/$UPDATE_VERSION/opendj/"
OPENDJ_SCHEMA_DIR="/opt/opendj/config/schema"
BACKUP_TIME=`date +%Y-%m-%d.%H:%M:%S`
BACKUP_FOLDER="/opt/upd/$UPDATE_VERSION/backup_opendj_$BACKUP_TIME"

echo "Starting the update process..."
service opendj stop

mkdir -p $BACKUP_FOLDER

if [ -f $OPENDJ_SCHEMA_DIR/101-ox.ldif ]; then
    echo "Updating 101-ox.ldif...."
    mv $OPENDJ_SCHEMA_DIR/101-ox.ldif $BACKUP_FOLDER
    cp $UPD_DIR/101-ox.ldif $OPENDJ_SCHEMA_DIR
    chown ldap:ldap $OPENDJ_SCHEMA_DIR/101-ox.ldif
fi

service opendj start
echo "Successfully updated"
