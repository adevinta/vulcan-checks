#!/usr/bin/env bash

# Copyright 2023 Adevinta

cd "$(dirname "$0")"
while true; do cat intel-amt.http | nc -l 16992 -q 1; done
