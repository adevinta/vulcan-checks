#!/bin/bash

# Copyright 2023 Adevinta

########################
# Executes vulcan-local with the provided parameters
# Arguments: vulcan-local params except -r that it's managed internally
# Exists 1 if not all check end with FINISHED status.
vulcan_local_test() {
    echo "Testing with vulcan-local $*"
    local tmp
    tmp=$(mktemp -d)
    vulcan-local "$@" -r - 2> "$tmp/error.log" 1> "$tmp/report.json" || true
    STATUS=$(jq < "$tmp/report.json" -r '.[].status' | tr '\n' ',')
    echo "Testing results $STATUS"
    if [[ ! $STATUS =~ ^(FINISHED|,)+$ ]]; then
        echo "Report:"
        jq < "$tmp/report.json"
        echo "Logs:"
        cat "$tmp/error.log"
        exit 1
    fi
}
