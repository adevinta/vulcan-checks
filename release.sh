#!/bin/bash

# Copyright 2020 Adevinta

# shellcheck disable=SC1091

set -e

trap "exit" INT

# Load Libraries
. _scripts/libgit.sh
. _scripts/libdocker.sh

get_tag_check() {
    local -r object_path="${1:?path to object argument required}"
    echo "$(git_commit_id go.mod)-$(git_commit_id "$object_path")"
}

# Load required env vars
eval "$(git_env)"
eval "$(dkr_env)"

LOG_TIME=$(date +"%s")

log_msg() {
    local previous=$LOG_TIME
    LOG_TIME=$(date +"%s")
    echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') [$((LOG_TIME-previous))s] -- $1"
}

PLATFORMS=${PLATFORMS:-"linux/arm64 linux/amd64"}
BRANCH=${TRAVIS_BRANCH:-$(git_branch .)}
BRANCH=${BRANCH//\//-}   # Replace / with - for branch names such as dependabot generated ones

IMAGE_TAGS=()
CACHE_TAGS=(edge)
if [[ $BRANCH == "master" ]]; then
    IMAGE_TAGS+=(latest edge)
    FORCE_BUILD="${FORCE_BUILD:-true}"
    ADD_TAG_CHECK=true
elif [[ $TRAVIS_TAG != "" ]]; then
    IMAGE_TAGS+=("$TRAVIS_TAG")
    FORCE_BUILD="${FORCE_BUILD:-true}"
    ADD_TAG_CHECK=false
else
    IMAGE_TAGS+=("$BRANCH" "$BRANCH-$(git rev-parse --short HEAD)")
    FORCE_BUILD="${FORCE_BUILD:-false}"
    ADD_TAG_CHECK=true
    CACHE_TAGS+=("$BRANCH")  # First time will print a message => ERROR importing cache manifest from XXXX
fi

log_msg "Starting FORCE_BUILD=$FORCE_BUILD"

CHECKS=()
for cf in cmd/*; do
    check=$(basename "$cf")
    if [[ $FORCE_BUILD == "false" ]]; then
        TAG_CHECK="$(get_tag_check "cmd/$check")"
        # Check if check version (code+dep) has been already pushed to Registry
        if [[ $(dkr_image_exists "$check" "$TAG_CHECK") == true ]]; then
            echo "Skipping $DKR_USERNAME/$check:$TAG_CHECK exists"
            continue
        fi
    fi
    CHECKS+=("$check")
done

log_msg "Computed list of checks to build: [${CHECKS[*]}]"

if [ ${#CHECKS[@]} -eq 0 ]; then
    exit
fi

# Download go dependencies
go mod download
log_msg "Downloaded go mod"

# Login into registry (authenticated pulls)
dkr_login > /dev/null

if ! docker buildx inspect multiarch; then
    # see https://github.com/docker/buildx/issues/495#issuecomment-761562905
    docker run --rm -it --privileged multiarch/qemu-user-static --reset -p yes
    docker buildx create --name multiarch --driver docker-container --use --bootstrap
    log_msg "Created buildx"
fi

# Generate a checktypes for the current tag.
TEST_TAG="${IMAGE_TAGS[0]}"

# Generate a checktypes.json that could be used later on for testint with vulcan-local.
vulcan-check-catalog -registry-url "$DKR_USERNAME" -tag "$TEST_TAG" -output checktypes.json cmd/
log_msg "Generated checktypes.json file with tags $TEST_TAG"
export VULCAN_CHECKTYPES=./checktypes.json

BUILDX_ARGS=()
BUILDX_ARGS+=("--label" "org.opencontainers.image.revision=$(git rev-parse --short HEAD)")
BUILDX_ARGS+=("--label" "org.opencontainers.image.ref=https://github.com/adevinta/vulcan-checks")

# Iterate over all checks
for check in "${CHECKS[@]}"; do

    CHECK_PLATFORMS=$PLATFORMS
    if [[ $check =~ $ARM64_EXCLUDE ]]; then
        CHECK_PLATFORMS=${PLATFORMS// linux\/arm64/}
    else
        CHECK_PLATFORMS=$PLATFORMS
    fi

    # Build the go app
    for PLATFORM in $CHECK_PLATFORMS; do
        OS=$(echo "$PLATFORM" | cut -f1 -d/)
        ARCH=$(echo "$PLATFORM" | cut -f2 -d/)
        CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH go build -ldflags="-s -w" -o "cmd/$check/$OS/$ARCH/$check" "$PWD/cmd/$check"
        log_msg "Builded go $check:$PLATFORM"
    done

    BUILDX_CHECK_ARGS=()
    for tag in "${CACHE_TAGS[@]}"; do
        BUILDX_CHECK_ARGS+=("--cache-from" "type=registry,ref=$DKR_USERNAME/$check:$tag")
    done

    if [ -x "cmd/$check/test.sh" ]; then
        log_msg "Builded test image $DKR_USERNAME/$check:$TEST_TAG"

        # Build the image without pushing
        docker buildx build "${BUILDX_CHECK_ARGS[@]}" \
            --tag "$DKR_USERNAME/$check:$TEST_TAG" \
            --platform="linux/amd64" \
            "cmd/$check" --load

        log_msg "Testing image $DKR_USERNAME/$check:$TEST_TAG"
        . "cmd/$check/test.sh" "$check"
    fi

    for tag in "${IMAGE_TAGS[@]}"; do
        BUILDX_CHECK_ARGS+=("--tag" "$DKR_USERNAME/$check:$tag")
    done
    if [[ $ADD_TAG_CHECK == "true" ]]; then
        BUILDX_CHECK_ARGS+=("--tag" "$DKR_USERNAME/$check:$(get_tag_check "cmd/$check")")
    fi

    docker buildx build "${BUILDX_ARGS[@]}" "${BUILDX_CHECK_ARGS[@]}" \
        --cache-to "type=inline" \
        --label "org.opencontainers.image.title=$check" \
        --label "org.opencontainers.image.created=$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --platform="${CHECK_PLATFORMS// /,}" \
        "cmd/$check" --push

    log_msg "Pushed image $check:[${IMAGE_TAGS[*]}]"
done

docker buildx rm multiarch
