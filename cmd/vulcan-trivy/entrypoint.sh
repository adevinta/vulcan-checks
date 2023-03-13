#!/bin/sh

# Copyright 2020 Adevinta

set -e

find /root/.cache/ -name "*.gz" -exec gunzip {} \;

# run check
./vulcan-trivy "$@"
