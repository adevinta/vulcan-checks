#!/bin/bash

# Copyright 2020 Adevinta
#
# This script contains the logic for build and push Vulcan
# checks available in `cmd` folder to Docker Hub registry.

# shellcheck disable=SC1091

# Force build even if conditions are not meet
# Force does not override EXCLUDE_LIST_FILE
FORCE_BUILD="${FORCE_BUILD:-false}"
# Force push even if conditions are not meet
# Force does not override EXCLUDE_LIST_FILE
FORCE_PUSH="${FORCE_PUSH:-false}"
# Skip push even if conditions are meet
# Force push prevails over Skip push
SKIP_PUSH="${SKIP_PUSH:-false}"
# Add time metrics to output
PRINT_METRICS="${PRINT_METRICS:-true}"
# Checks to exclude from build and push
EXCLUDE_LIST_FILE="${EXCLUDE_LIST_FILE:-_scripts/exclude.lst}"
BASE_PATH="$PWD"

# Load Libraries
. _scripts/libgit.sh
. _scripts/libdocker.sh

# Load required env vars
eval "$(git_env)"
eval "$(dkr_env)"

# Login into registry (authenticated pulls)
dkr_login > /dev/null

docker pull alpine
