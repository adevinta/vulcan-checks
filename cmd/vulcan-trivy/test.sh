#!/bin/bash

set -eu

. _scripts/libtest.sh

vulcan_local_test -i "$1" -t docker.io/busybox:alpine -a DockerImage -t .
