#!/bin/bash

set -eu

. _scripts/libtest.sh

# Validate custom templates.
docker run --rm -v ./cmd/vulcan-nuclei/templates:/tmp/templates projectdiscovery/nuclei -duc -validate -ud /tmp/templates

CONTAINERID1=$(docker run -p 21:21 -d garethflowers/ftp-server:0.6.0)
CONTAINERID2=$(docker run -p 6379:6379 -d redis:7.2-alpine)
trap finish EXIT
function finish {
    docker rm -f "$CONTAINERID1" || true
    docker rm -f "$CONTAINERID2" || true
}

vulcan_local_test -i "$1" -t localhost -a Hostname -o '{"tag_inclusion_list":["ftp", "detect"]}'
