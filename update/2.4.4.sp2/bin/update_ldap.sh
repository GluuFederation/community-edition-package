#!/bin/bash

UPDATE_VERSION="2.4.4.sp2"
BACKUP_TIME=`date +%Y-%m-%d.%H:%M:%S`
BACKUP_FOLDER="/opt/upd/$UPDATE_VERSION/backup_ldap_$BACKUP_TIME"

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
        return 1
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
        echo "Failed to prepare gluuStatus attribute metadata backup before updating LDAP"
        return 2
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
        return 3
    fi

    echo "Update was applied successfully"

    return 0
}
# END: Update for gluuStatus meta-data

# START: Update for oxAuth configuration


add_json_configuration_option() {
    FILE_NAME=$1
    CONFIGURATION_KEY=$2
    CONFIGURATION_OPTION=$3

    EXIST_CONFIGURATION_KEY=`cat $FILE_NAME | grep $CONFIGURATION_KEY`
    if [[ ! -z $EXIST_CONFIGURATION_KEY ]]; then
        # Configuraton alredy has this option
        return 0
    fi

    # Create copy without last "}"
    cat $FILE_NAME > $FILE_NAME.tmp
    cat $FILE_NAME.tmp | grep -v "^}$" > $FILE_NAME
    rm -f $FILE_NAME.tmp

    echo -e $CONFIGURATION_OPTION >> $FILE_NAME

    return 1
}

apply_update2() {
    # Check if oxAuth configuration updated already
    echo "Checking if oxAuth configuration need to be updated..."

    # Determine oxAuth config LDAP DN
    OXAUTH_CONFIG_DN=`cat /opt/tomcat/conf/ox-ldap.properties | grep "^oxauth_ConfigurationEntryDN: " | awk -F"=" '{print $2}'`

    mkdir -p $BACKUP_FOLDER

    # Export entry which we are going to update
    echo "Creating backup before updating LDAP"
    BACKUP_FILE=$BACKUP_FOLDER/oxauth_config.ldif
    /opt/opendj/bin/ldapsearch -h localhost -p 1636 -Z -X -T -D "cn=Directory Manager" -j $LDAP_PWD_FILE -b "$OXAUTH_CONFIG_DN" 'objectClass=oxAuthConfiguration' > $BACKUP_FILE
    if [ $? -ne 0 ]; then
        echo "Failed to prepare oxAuth configuration backup before updating LDAP"
        return 1
    fi

    OXAUTH_DYNAMIC_CONFIG_FILE=$BACKUP_FOLDER/oxauth_dynamic.json
    BASE_64_ENCODED=`cat $BACKUP_FILE | grep "^oxAuthConfDynamic:: " | wc -l`
    if [[ $BASE_64_ENCODED == 0 ]]; then
        # Value is not base64 encoded
        cat $BACKUP_FILE | grep "^oxAuthConfDynamic: " | awk -F": " '{print $2}' | python -m json.tool > $OXAUTH_DYNAMIC_CONFIG_FILE
    else
        # Value is base64 encoded
        cat $BACKUP_FILE | grep "^oxAuthConfDynamic:: " | awk -F":: " '{print $2}' | base64 --decode | python -m json.tool > $OXAUTH_DYNAMIC_CONFIG_FILE
    fi

    COUNT_CHANGES=0
    add_json_configuration_option $OXAUTH_DYNAMIC_CONFIG_FILE '"defaultSubjectType"' ',"defaultSubjectType": "pairwise"\n}'
    ((COUNT_CHANGES+=$?))
    add_json_configuration_option $OXAUTH_DYNAMIC_CONFIG_FILE '"endSessionWithAccessToken"' ',"endSessionWithAccessToken": false\n}'
    ((COUNT_CHANGES+=$?))
    add_json_configuration_option $OXAUTH_DYNAMIC_CONFIG_FILE '"clientWhiteList"' ',"clientWhiteList": ["*"]\n}'
    ((COUNT_CHANGES+=$?))
    add_json_configuration_option $OXAUTH_DYNAMIC_CONFIG_FILE '"clientBlackList"' ',"clientBlackList": ["*.attacker.com/*"]\n}'
    ((COUNT_CHANGES+=$?))
    add_json_configuration_option $OXAUTH_DYNAMIC_CONFIG_FILE '"legacyIdTokenClaims"' ',"legacyIdTokenClaims": true\n}'
    ((COUNT_CHANGES+=$?))

    if [[ $COUNT_CHANGES == 0 ]]; then
        echo "All new configuration options added already"
        return 0
    fi

    echo "Preparing update operation"
    OXAUTH_CONF_DYNAMIC_BASE64=`base64 --wrap 0 < $OXAUTH_DYNAMIC_CONFIG_FILE`
    UPDATE_FILE=$BACKUP_FOLDER/oxauth_config_update.ldif
    cat $BACKUP_FILE | grep "^dn: " > $UPDATE_FILE
    echo "changetype: modify" >> $UPDATE_FILE
    echo "replace: oxAuthConfDynamic" >> $UPDATE_FILE
    echo "oxAuthConfDynamic:: $OXAUTH_CONF_DYNAMIC_BASE64" >> $UPDATE_FILE
    echo "" >> $UPDATE_FILE

    echo "Applying update"
    /opt/opendj/bin/ldapmodify -h localhost -p 1636 -Z -X -D "cn=Directory Manager" -j $LDAP_PWD_FILE -f $UPDATE_FILE
    if [ $? -ne 0 ]; then
        echo "Failed to apply LDAP update"
        return 2
    fi

    echo "Update was applied successfully"

    return 0
}
# END: Update for oxAuth configuration

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
apply_update2

finish
