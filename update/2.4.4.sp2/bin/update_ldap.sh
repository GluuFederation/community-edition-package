#!/bin/sh

BACKUP_TIME=`date +%Y-%m-%d.%H:%M:%S`
BACKUP_FOLDER="/opt/upd/2.4.4.sp1/backup_ldap_$BACKUP_TIME"

init () {
    # Prapre required data
    echo "Preparing for appling updates..."

    # Determine Gluu LDAP password
    LDAP_PWD=`cat /opt/tomcat/conf/ox-ldap.properties | grep "^bindPassword: " | awk -F": " '{print $2}' | xargs -0 -I {} /opt/gluu/bin/encode.py -d {}`
    if [ $? -ne 0 ]; then
        echo "Failed to determine Gluu LDAP password"
        return 1
    fi
    LDAP_PWD_FILE=/home/ldap/.pw
    echo $LDAP_PWD > $LDAP_PWD_FILE

    return 0
}

# START: Update for gluuStatus meta-data
apply_update1() {
    # Check if there are 2 same meta-data attributes
    echo "Checking if LDAP need to be updated..."
    GLUU_STATUS_COUNT=`/opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -T -D "cn=Directory Manager" -j $LDAP_PWD_FILE -b "o=gluu" '&(objectClass=gluuAttribute)(gluuAttributeName=gluuStatus)' | grep "^dn: " | wc -l`
    if [ $? -ne 0 ]; then
        echo "Failed to get data from LDAP server"
        return 2
    fi

    if [[ $GLUU_STATUS_COUNT < 2 ]]; then
        echo "There is only one gluuStatus meta-data. Update is not required"
        return 0
    fi

    mkdir -p $BACKUP_FOLDER

    # Export entry which we are going to remove
    echo "Creating backup before updating LDAP"
    BACKUP_FILE=$BACKUP_FOLDER/gluustatus_attribute.ldif
    /opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -T -D "cn=Directory Manager" -j $LDAP_PWD_FILE -b "o=gluu" '&(objectClass=gluuAttribute)(inum=*!0005!42E2)' > $BACKUP_FILE
    if [ $? -ne 0 ]; then
        echo "Failed to prepare backup before updating LDAP"
        return 3
    fi

    echo "Preparing update operation"
    UPDATE_FILE=$BACKUP_FOLDER/gluustatus_attribute_update.ldif
    cat $BACKUP_FILE | grep "^dn: " > $UPDATE_FILE
    echo "changetype: delete" >> $UPDATE_FILE
    echo "" >> $UPDATE_FILE

    echo "Applying update"
    /opt/opendj/bin/ldapmodify -h localhost -p 1636 -Z -X -D "cn=Directory Manager" -j $LDAP_PWD_FILE -f $UPDATE_FILE
    if [ $? -ne 0 ]; then
        echo "Failed to apply LDAP update"
        return 4
    fi

    echo "Update was applied successfully"

    return 0
}
# END: Update for gluuStatus meta-data

finish() {
    echo "Removing temporary data"
    rm -rf $LDAP_PWD_FILE

    return 0
}

init
if [ $? -ne 0 ]; then
    exit $?
fi

apply_update1
finish
