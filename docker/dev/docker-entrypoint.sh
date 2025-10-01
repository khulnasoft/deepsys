#!/bin/bash
#set -e

echo "* Setting up /usr/src links from host"

if [ -d "$DEEPSYS_HOST_ROOT/usr/src" ]; then
    for i in "$DEEPSYS_HOST_ROOT"/usr/src/*; do
        if [ -e "$i" ]; then
            ln -s "$i" /usr/src/
        fi
    done
fi

/usr/bin/deepsys-probe-loader

exec "$@"
