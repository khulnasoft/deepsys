#!/bin/bash
set -e
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DUSE_BUNDLED_LUAJIT=OFF -DUSE_BUNDLED_ZLIB=OFF
make install
../test/deepsys_trace_regression.sh $(which deepsys) ./userspace/deepsys/chisels $TRAVIS_BRANCH
