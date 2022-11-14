#!/bin/bash

# Copyright 2022 Adevinta

set -e

mkdir pages/checktypes

go install "github.com/adevinta/vulcan-check-catalog/cmd/vulcan-check-catalog@${VCC_VERSION:-main}"

if [[ $TRAVIS_BRANCH == "master" ]]; then
    vulcan-check-catalog -registry-url "$DKR_USERNAME" -tag edge -output pages/checktypes/edge.json cmd/
else
    echo "Skipping because not in master branch"
fi
