#!/bin/bash

set -eu

. _scripts/libtest.sh


CONTAINERID=$(docker run -p 21:21 -d garethflowers/ftp-server:0.6.0)
trap finish EXIT
function finish {
    docker rm -f "$CONTAINERID" || true
}

vulcan_local_test -i "$1" -t localhost -a Hostname -o '{"tag_inclusion_list":["ftp"]}'
