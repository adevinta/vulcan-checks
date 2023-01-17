#!/usr/bin/env bash

# Copyright 2023 Adevinta

while true; do cat varnish-cache.http | nc -l 7002 -q 1; done
