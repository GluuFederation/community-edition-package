#!/bin/bash

export JAVA_HOME=/opt/jre
export OPENDJ_JAVA_HOME=${JAVA_HOME}
export JETTY_HOME=/opt/jetty
export PATH=$PATH:$JAVA_HOME/bin:$NODE_HOME/bin:/opt/opendj/bin
export PYTHONPATH=/usr/lib/python3.6/gluu-packaged/
