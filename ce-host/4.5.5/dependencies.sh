#!/bin/bash

if ! [ -z $(grep -i "centos-8" /etc/os-release) ]
then
    yum install -y epel-release
    if !  command -v python3 > /dev/null 2>&1 ; then
        yum install -y python3
    fi
    yum install -y python3-six python3-ldap3 python3-requests

fi

python3 /opt/gluu/bin/install.py
