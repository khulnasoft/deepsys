#!/bin/bash
#set -e

echo "* Setting up /usr/src links from host"

for i in $DEEPSYS_HOST_ROOT/usr/src/*
do
	ln -s "$i" /usr/src/
done

/usr/bin/deepsys-probe-loader

exec "$@"
