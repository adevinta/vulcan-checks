#!/usr/bin/env bash

# Copyright 2023 Adevinta

cd "$(dirname "$0")"
while true; do cat hdfs.http | nc -l 14000 -q 1; done 
