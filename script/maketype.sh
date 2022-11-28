#!/bin/sh

if [ $# -ne 2 ]; then
    echo "$0 header object"
    exit 1
fi

gcc -g -fno-eliminate-unused-debug-types -x c -c $1 -o $2
