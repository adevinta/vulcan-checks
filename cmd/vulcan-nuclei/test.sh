#!/bin/bash

set -eu

. _scripts/libtest.sh


CONTAINERID=$(docker run -p 21:21 -d delfer/alpine-ftp-server)
trap finish EXIT
function finish {
    docker rm -f "$CONTAINERID" || true
}

vulcan_local_test -i "$1" -t http://localhost -o '{"tag_inclusion_list":["ftp"]}'
