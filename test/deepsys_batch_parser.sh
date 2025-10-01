#!/bin/bash

set -eu

DEEPSYS=$1
DEEPSYS_CHISEL_DIR=$2
ARGS=$3
TRACESDIR=$4
DIRNAME=$5
REFERENCEDIR=$6

export DEEPSYS_CHISEL_DIR

unamestr=`uname`
if [[ "$unamestr" == 'Linux' ]]; then
	TIMEOUT_BIN="timeout"
elif [[ "$unamestr" == 'Darwin' ]]; then
	TIMEOUT_BIN="gtimeout"
fi

rm -rf $DIRNAME || true
mkdir -p $DIRNAME

if [ ! -e $REFERENCEDIR ]; then
    echo "Reference directory $REFERENCEDIR does not exist--skipping directory entirely"
    exit 0
fi

for f in $TRACESDIR/*
do
    ref=$REFERENCEDIR/$(basename $f).output;
    if [ ! -e $ref ]; then
	echo "Corresponding reference file $ref does not exist--skipping"
    else
	echo "Processing $f"
	TZ=UTC eval ${TIMEOUT_BIN} 60 $DEEPSYS -r $f $ARGS > $DIRNAME/$(basename $f).output
    fi
done

echo Data saved in $DIRNAME

diff -r $DIRNAME $REFERENCEDIR
rm -rf $DIRNAME
