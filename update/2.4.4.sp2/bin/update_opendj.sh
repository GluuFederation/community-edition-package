#!/bin/sh

UPD_DIR="/opt/upd/2.4.4.sp1/opendj/"
OPENDJ_SCHEMA_DIR="/opt/opendj/config/schema"
BACKUP_TIME=`date +%Y-%m-%d.%H:%M:%S`
BACKUP_FOLDER="/opt/upd/2.4.4.sp1/backup_opendj_$BACKUP_TIME"

echo "Starting the update process..."
service opendj stop

mkdir -p $BACKUP_FOLDER

if [ -f $OPENDJ_SCHEMA_DIR/101-ox.ldif ]; then
    echo "Updating 101-ox.ldif...."
    mv $OPENDJ_SCHEMA_DIR/101-ox.ldif $BACKUP_FOLDER
    cp $UPD_DIR/101-ox.ldif $OPENDJ_SCHEMA_DIR
fi

service opendj start
echo "Successfully updated"
