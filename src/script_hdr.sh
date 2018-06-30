#!/bin/bash

tail -n +11 "$0" | g++ -xc++ -o /tmp/minihttp_$USER -std=c++17 -Wall -Wno-subobject-linkage -O2 - -lpthread -lstdc++fs
/tmp/minihttp_$USER $*
RESULT=$?
rm -f /tmp/minihttp_$USER
exit $RESULT




//begin of c++ source
