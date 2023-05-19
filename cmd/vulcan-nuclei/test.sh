#!/bin/bash

set -eu

. _scripts/libtest.sh

CONTAINERID=$(docker run -p 9999:80 -d nginx)
trap finish EXIT
function finish {
    docker rm -f "$CONTAINERID" || true
}

vulcan_local_test -i "$1" -t http://localhost:9999 -o '{"tag_inclusion_list":["smtp"]}'
