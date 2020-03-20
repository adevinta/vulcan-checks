#!/bin/sh

set -e

# untar trivy cache file
tar xf trivy_cache.tgz

# run check
./vulcan-trivy "$@"
