#!/bin/sh

# Copyright 2020 Adevinta

set -e

if [ -d /root/.cache ]; then
    find /root/.cache/ -name "*.gz" -exec gunzip {} \;
fi

# run check
./vulcan-trivy "$@"
