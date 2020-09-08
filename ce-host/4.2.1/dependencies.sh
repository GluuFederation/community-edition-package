#!/bin/bash

if command -v yum > /dev/null 2>&1; then
    yum install -y epel-release

    if !  command -v python3 > /dev/null 2>&1 ; then
        yum install -y python3
    fi

    yum install -y python36-six python3-ldap3 python3-requests


else
    echo "Do apt commands"

fi

python3 /opt/gluu/bin/install.py

#./makeself.sh --target / /opt/gluu-server-4.2.1-host gluu-server-4.2.1-host.sh "Gluu CE Package 4.2.1" /opt/gluu/bin/dependencies.sh
