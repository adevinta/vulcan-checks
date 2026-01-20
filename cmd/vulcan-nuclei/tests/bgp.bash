#!/usr/bin/env bash

# Copyright 2023 Adevinta

cd "$(dirname "$0")"
while true; do echo -n -e "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" | nc -l 179; done
