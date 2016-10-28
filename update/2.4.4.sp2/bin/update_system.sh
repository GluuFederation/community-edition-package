#!/bin/sh

UPDATE_VERSION="2.4.4.sp2"

# Fix Asimba JKS permissions
/bin/chmod u+w /etc/certs/asimbaIDP.jks

echo "Successfully updated"
