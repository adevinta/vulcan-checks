#!/bin/sh

# Copyright 2020 Adevinta

set -e

# untar trivy cache file
tar xvf /root/cache.tgz -C /root
rm /root/cache.tgz

# run check
./vulcan-trivy "$@"
