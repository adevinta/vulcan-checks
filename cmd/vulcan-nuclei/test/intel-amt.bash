#!/usr/bin/env bash

# Copyright 2019 Adevinta

while true; do cat intel-amt.http | nc -l 16992 -q 2; done
