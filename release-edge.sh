#!/bin/bash

# Copyright 2020 Adevinta

# shellcheck disable=SC1091

BASE_PATH="$PWD"

# Load Libraries
. _scripts/libgit.sh
. _scripts/libdocker.sh

# Load required env vars
eval "$(git_env)"
eval "$(dkr_env)"

# Login into registry (authenticated pulls)
dkr_login > /dev/null

# Download go dependencies
go mod download

# Iterate over all checks
for cf in cmd/*; do
    check=$(basename "$cf")
    echo "Procesing $check"

    # List of tags to apply to check Docker image
    tag_list="latest,edge"

    # Build check (Go binaries and Docker images + Tagging)
    cd "$cf" || exit 1
    CGO_ENABLED=0 go build .
    cd "$BASE_PATH" || exit 1

    # Build docker image
    dkr_build "$cf" "$check"

    # Tag docker image
    dkr_tag "$check" "$tag_list"

    # Push all the tags
    dkr_push_tags "$check" "$tag_list"
done
