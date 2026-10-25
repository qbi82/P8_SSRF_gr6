#!/bin/sh
set -eu
if [ "${ENABLE_EGRESS:-0}" = "1" ]; then
  /srv/egress-rules.sh
fi
# No network administration privileges remain in the application process.
exec setpriv --reuid=10001 --regid=10001 --clear-groups --bounding-set=-all python /srv/app.py
