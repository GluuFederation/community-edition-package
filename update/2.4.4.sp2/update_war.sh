#!/bin/sh

UPD_DIR="/opt/upd/2.4.4.sp1/war/"
OXIDP="/opt/idp/war/"
OXCAS="/opt/dist/"
TOMCAT_DIR="/opt/tomcat/webapps/"
BACKUP_TIME=`date +%Y-%m-%d.%H:%M:%S`
BACKUP_FOLDER="/opt/upd/2.4.4.sp1/backup_$BACKUP_TIME"

echo "Starting the update process..."
service tomcat stop

mkdir -p $BACKUP_FOLDER

if [ -f $TOMCAT_DIR/oxauth.war ]; then
    echo "Updating oxAuth...."
    if [ -d $TOMCAT_DIR/oxauth ]; then
        mv $TOMCAT_DIR/oxauth $BACKUP_FOLDER
    fi
    mv $TOMCAT_DIR/oxauth.war $BACKUP_FOLDER
    cp $UPD_DIR/oxauth.war $TOMCAT_DIR
fi

if [ -f $OXIDP/idp.war ]; then
    echo "Updating IDP..."
    mv $OXIDP/idp.war $BACKUP_FOLDER
    cp $UPD_DIR/idp.war $OXIDP
fi

if [ -f $TOMCAT_DIR/cas.war ]; then
    echo "Updating Cas..."
    if [ -d $TOMCAT_DIR/cas ]; then
        mv $TOMCAT_DIR/cas $BACKUP_FOLDER
    fi
    mv $TOMCAT_DIR/cas.war $BACKUP_FOLDER
    cp $UPD_DIR/oxcas.war $TOMCAT_DIR/cas.war
fi

if [ -f $TOMCAT_DIR/identity.war ]; then
    echo "Updating Identify..."
    if [ -d $TOMCAT_DIR/identity ]; then
        mv $TOMCAT_DIR/identity $BACKUP_FOLDER
    fi
    mv $TOMCAT_DIR/identity.war $BACKUP_FOLDER
    cp $UPD_DIR/identity.war $TOMCAT_DIR
fi

service tomcat start
echo "Successfully updated"
