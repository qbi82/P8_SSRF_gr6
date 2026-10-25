#!/bin/sh
# Canonical implementation is copied into the app image.
set -eu
exec "$(dirname "$0")/../app/egress-rules.sh"
