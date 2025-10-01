#!/bin/bash
#set -e

echo "* Setting up /usr/src links from host"

for i in $(ls $DEEPSYS_HOST_ROOT/usr/src)
do 
	ln -s $DEEPSYS_HOST_ROOT/usr/src/$i /usr/src/$i
done

/usr/bin/deepsys-probe-loader

exec "$@"
