#!/bin/sh

UPDATE_VERSION="2.4.4.sp2"
UPD_DIR="/opt/upd/$UPDATE_VERSION/war/"
OXIDP="/opt/idp/war/"
OXCAS="/opt/dist/"
TOMCAT_DIR="/opt/tomcat/webapps/"
BACKUP_TIME=`date +%Y-%m-%d.%H:%M:%S`
BACKUP_FOLDER="/opt/upd/$UPDATE_VERSION/backup_$BACKUP_TIME"

apply_update () {
    APP_NAME=$1
    if [ -f $TOMCAT_DIR/$APP_NAME.war ]; then
        echo "Updating $APP_NAME...."
        if [ -d $TOMCAT_DIR/$APP_NAME ]; then
            mv $TOMCAT_DIR/$APP_NAME $BACKUP_FOLDER
        fi
        mv $TOMCAT_DIR/$APP_NAME.war $BACKUP_FOLDER
        cp $UPD_DIR/$APP_NAME.war $TOMCAT_DIR
    fi
}

apply_idp_update () {
    if [ -f $OXIDP/idp.war ]; then
        echo "Updating IDP..."
        mv $OXIDP/idp.war $BACKUP_FOLDER
        cp $UPD_DIR/idp.war $OXIDP
    fi
}
echo "Starting the update process..."
service tomcat stop

mkdir -p $BACKUP_FOLDER

apply_update oxauth
apply_update identity
#apply_update cas
apply_idp_update


service tomcat start
echo "Successfully updated"
