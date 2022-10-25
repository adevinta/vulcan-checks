#!/bin/bash

# Copyright 2020 Adevinta

# shellcheck disable=SC1091

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

PLATFORMS=${PLATFORMS:-"linux/arm64 linux/amd64"}

for PLATFORM in $PLATFORMS; do
    echo "Building checks $PLATFORM"
    OS=$(echo "$PLATFORM" | cut -f1 -d/)
    ARCH=$(echo "$PLATFORM" | cut -f2 -d/)
    CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH go build -ldflags="-s -w" -o "build/$OS/$ARCH/" ./...
done

docker buildx create --name mybuilder --use --bootstrap

# Iterate over all checks
for cf in cmd/*; do
    check=$(basename "$cf")
    echo "Procesing $check"

    # move the files from build to the check directory.
    find build -type f -name "$check" -exec sh -c '
    for file do
        target=cmd/$(basename $file)/$(dirname "${file#build/}")
        mkdir -p $target
        mv $file $target
    done' sh {} +

    docker buildx build \
        --cache-from "type=registry,ref=$DKR_USERNAME/$check:latest" \
        --cache-to "type=inline" \
        --label "org.opencontainers.image.title=$check" \
        --label "org.opencontainers.image.ref=https://github.com/adevinta/vulcan-checks" \
        --label "org.opencontainers.image.created=$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --label "org.opencontainers.image.revision=$(git rev-parse --short HEAD)" \
        --tag "$DKR_USERNAME/$check:latest" \
        --tag "$DKR_USERNAME/$check:edge" \
        --platform="${PLATFORMS// /,}" \
        "$cf" --push

    break
done

docker buildx rm mybuilder
