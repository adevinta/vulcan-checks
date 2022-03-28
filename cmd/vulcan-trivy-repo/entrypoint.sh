#!/bin/sh

# Copyright 2020 Adevinta

set -e

# untar trivy cache file
tar xf trivy_cache.tgz

# run check
./vulcan-trivy-repo "$@"
