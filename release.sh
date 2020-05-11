#!/bin/bash
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
# Add time metrics to output
PRINT_METRICS="${PRINT_METRICS:-true}"
# Checks to exclude from build and push
EXCLUDE_LIST_FILE="${EXCLUDE_LIST_FILE:-_scripts/exclude.lst}"
# Sleep 1 second between registry calls
REGISTRY_RATE_LIMIT="${REGISTRY_RATE_LIMIT:-true}"
BASE_PATH="$PWD"

# Load Libraries
. _scripts/libgit.sh
. _scripts/libdocker.sh

# Load required env vars
eval "$(git_env)"
eval "$(dkr_env)"

# Fetch dependency version and modification timestamp
dep_version=$(git_commit_id go.mod)
dep_timestamp=$(git_timestamp go.mod)

# Fetch branch and check mode (master or experimental)
branch=$(git_branch .)
check_branch=${TRAVIS_BRANCH:-$branch}
check_mode=${TRAVIS_BRANCH:-$branch}
if [ "$check_mode" != "master" ]; then
    check_mode="experimental"
fi

# Download go dependencies
go mod download

# Iterate over all checks
for cf in cmd/*; do
    do_build=true
    do_push=true

    ts_start=$(date +"%s")
    # Verify only directories are processed
    if [ ! -d "$cf" ]; then
        continue
    fi
    check=$(basename "$cf")
    # Verify if check is in the exlude list
    if grep -q "$check" "$EXCLUDE_LIST_FILE"; then
        echo "Skip build and push for check: [$check] - EXCLUDED"
        continue
    fi
    # Fetch check version and modification timestamp
    check_version=$(git_commit_id "$cf")
    check_timestamp=$(git_timestamp "$cf")

    # Check if check has been pushed due to code or dependency update
    pushed_by_dependency=$(dkr_image_exists "$check" "dep-$dep_version")
    if [[ $REGISTRY_RATE_LIMIT == true ]]; then sleep 1; fi
    pushed_by_check_code=$(dkr_image_exists "$check" "$check_version")

    # Check has been already pushed to Registry
    if [[ $pushed_by_dependency == true && $pushed_by_check_code == true ]]; then
        do_build=$FORCE_BUILD
        do_push=$FORCE_PUSH
        if [[ $do_build == false && $do_push == false ]]; then
            echo "Skip build and push for check: [$check] - ALREADY PUSHED"
            continue
        fi
        echo "Check: [$check] - ALREADY PUSHED - FORCE PUSH: $FORCE_PUSH"
    fi

    # Check if the image is available locally
    local_by_dependency=$(dkr_local_image_exists "$check" "dep-$dep_version")
    local_by_check_code=$(dkr_local_image_exists "$check" "$check_version")

    # If exists locally, we should build only if forced
    if [[ $local_by_dependency == true && $local_by_check_code == true ]]; then
        if [[ ! $FORCE_BUILD == true ]]; then
            do_build=false
        fi
    fi

    echo "Processing: [$check] | ID: $check_version TS: $check_timestamp DEP_ID: $dep_version MODE: $check_mode"
    # Build go binaries
    if [[ $do_build == true ]]; then
        cd "$cf" || exit 1
        ts_go_build_start=$(date +"%s")
        CGO_ENABLED=0 go build .
        ts_go_build_finish=$(date +"%s")
        cd "$BASE_PATH" || exit 1

        # Build docker image
        ts_docker_build_start=$(date +"%s")
        dkr_build "$cf" "$check"
        ts_docker_build_finish=$(date +"%s")

        # Tag docker image
        ts_docker_tag_start=$(date +"%s")
        dkr_tag "$check" "latest,$check_version,$check_timestamp,dep-$dep_version,dep-$dep_timestamp,$check_branch,$check_mode"
        ts_docker_tag_finish=$(date +"%s")
    else
        echo "Skip build process for check: [$check]"
        ts_go_build_start=$(date +"%s")
        ts_go_build_finish=$(date +"%s")
        ts_docker_build_start=$(date +"%s")
        ts_docker_build_finish=$(date +"%s")
        ts_docker_tag_start=$(date +"%s")
        ts_docker_tag_finish=$(date +"%s")
    fi

    # Push docker image
    ts_docker_push_start=$(date +"%s")
    if [[ $do_push == true ]]; then
        dkr_push "$check"
    else
        echo "Skip push process for check: [$check]"
    fi
    ts_docker_push_finish=$(date +"%s")

    ts_finish=$(date +"%s")
    if [[ $PRINT_METRICS == true ]]; then
        total_process=$((ts_finish-ts_start))
        go_build=$((ts_go_build_finish-ts_go_build_start))
        docker_build=$((ts_docker_build_finish-ts_docker_build_start))
        docker_tag=$((ts_docker_tag_finish-ts_docker_tag_start))
        docker_push=$((ts_docker_push_finish-ts_docker_push_start))
        echo "## Build and push stats for check [$check]"
        echo "## $total_process seconds : total process"
        echo "## $go_build seconds : go build process"
        echo "## $docker_build seconds : docker build process"
        echo "## $docker_tag seconds : docker tag process"
        echo "## $docker_push seconds : docker push process"
        echo "### Stats: [$check] # Total: $total_process # Go Build: $go_build # Docker Build: $docker_build # Docker Tag: $docker_tag # Docker Push: $docker_push"
    fi
done
