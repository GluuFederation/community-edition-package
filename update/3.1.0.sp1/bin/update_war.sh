#!/bin/sh

UPDATE_VERSION="3.1.0.sp1"
UPD_DIR="/opt/upd/$UPDATE_VERSION/war/"
GLUU_BASE_DIR="/opt/gluu/jetty"
BACKUP_TIME=`date +%Y-%m-%d.%H:%M:%S`
BACKUP_FOLDER="/opt/upd/$UPDATE_VERSION/backup_$BACKUP_TIME"

apply_app_update () {
    APP_NAME=$1

    # Update if destination war exists
    if [ -f $GLUU_BASE_DIR/$APP_NAME/webapps/$APP_NAME.war ]; then
        echo "Updating $APP_NAME...."

        # Stop service
        service $APP_NAME stop

        # Update war file
        mv $GLUU_BASE_DIR/$APP_NAME/webapps/$APP_NAME.war $BACKUP_FOLDER
        cp $UPD_DIR/$APP_NAME.war $GLUU_BASE_DIR/$APP_NAME/webapps

        # Start service
        service $APP_NAME start
    fi
}

echo "Starting the update process..."

mkdir -p $BACKUP_FOLDER

apply_app_update oxauth
apply_app_update identity

echo "Successfully updated"
