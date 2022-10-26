#!/bin/bash

# Copyright 2020 Adevinta

# shellcheck disable=SC1091

trap "exit" INT

# Load Libraries
. _scripts/libgit.sh
. _scripts/libdocker.sh

# Load required env vars
eval "$(git_env)"
eval "$(dkr_env)"

LOG_TIME=$(date +"%s")

log_msg() {
    local previous=$LOG_TIME
    LOG_TIME=$(date +"%s")
    echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') [$((LOG_TIME-previous))s] -- $1"
}

# Download go dependencies
go mod download
log_msg "Downloaded go mod"

PLATFORMS=${PLATFORMS:-"linux/arm64 linux/amd64"}

# Building all the binaries is faster than one-by-one.
for PLATFORM in $PLATFORMS; do
    OS=$(echo "$PLATFORM" | cut -f1 -d/)
    ARCH=$(echo "$PLATFORM" | cut -f2 -d/)
    CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH go build -ldflags="-s -w" -o "build/$OS/$ARCH/" ./...
    log_msg "Builded checks $PLATFORM"
done

# move the files from build to the check directory.
find build -type f -exec sh -c '
for file do
    target=cmd/$(basename $file)/$(dirname "${file#build/}")
    mkdir -p $target
    mv $file $target
done' sh {} +

# Login into registry (authenticated pulls)
dkr_login > /dev/null

# see https://github.com/docker/buildx/issues/495#issuecomment-761562905
docker run --rm -it --privileged multiarch/qemu-user-static --reset -p yes
docker buildx create --name multiarch --driver docker-container --use --bootstrap
log_msg "Created buildx"

BUILDX_ARGS=()
BUILDX_ARGS+=("--label" "org.opencontainers.image.revision=$(git rev-parse --short HEAD)")
BUILDX_ARGS+=("--label" "org.opencontainers.image.ref=https://github.com/adevinta/vulcan-checks")

BRANCH=${TRAVIS_BRANCH:-$(git_branch .)}

TAGS=()
if [[ $BRANCH == "master" ]]; then
    TAGS+=(latest edge)
    FORCE_BUILD=true
elif [[ $TRAVIS_TAG != "" ]]; then
    TAGS+=("$TRAVIS_TAG")
    FORCE_BUILD=true
else
    TAGS+=("$BRANCH" "$BRANCH-$(git rev-parse --short HEAD)")
    FORCE_BUILD="${FORCE_BUILD:-false}"
fi

# Iterate over all checks
for cf in cmd/*; do
    check=$(basename "$cf")

    if [[ $FORCE_BUILD == "false" ]]; then
        TAG_CHECK="$(git_commit_id go.mod)-$(git_commit_id "$cf")"

        # Check if check version (code+dep) has been already pushed to Registry
        if [[ $(dkr_image_exists "$check" "$TAG_CHECK") == true ]]; then
            echo "Skip build and push for existing check image [$check:$TAG_CHECK]"
            continue
        fi
        TAGS+=("$TAG_CHECK")
    fi

    BUILDX_CHECK_ARGS=()
    for tag in "${TAGS[@]}"; do
        BUILDX_CHECK_ARGS+=("--tag" "$DKR_USERNAME/$check:$tag")
    done

    docker buildx build \
        --cache-from "type=registry,ref=$DKR_USERNAME/$check:latest" \
        --cache-to "type=inline" \
        --label "org.opencontainers.image.title=$check" \
        --label "org.opencontainers.image.created=$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --platform="${PLATFORMS// /,}" \
        "$cf" "${BUILDX_ARGS[@]}" "${BUILDX_CHECK_ARGS[@]}" --push

    log_msg "Builded $check:[${TAGS[*]}]"
done

docker buildx rm multiarch
