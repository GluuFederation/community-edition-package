#!/usr/bin/env sh

if [ -f "/usr/bin/python3" ]; then
    PY_CMD="/usr/bin/python3"
else
    PY_CMD="/usr/bin/python2"
fi

$PY_CMD /opt/upd/update_log4j/update_log4j.py
