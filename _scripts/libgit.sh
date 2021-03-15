#!/bin/bash

# Copyright 2020 Adevinta
#
# Git library

########################
# Load global variables used on Git configuration
# Globals:
#   GIT_*
# Arguments:
#   None
# Returns:
#   Series of exports to be used as 'eval' arguments
#########################
git_env() {
    cat <<"EOF"
EOF
}

########################
# Returns latest commit id for a given path (file or directory).
# Arguments:
#   $1 - Path (file or directory)
# Returns:
#   String
git_commit_id() {
    local -r object_path="${1:?path to object argument required}"
    git_execute --no-pager log -1 --pretty=tformat:"%h" "${object_path}"
}

########################
# Returns latest git modification timestamp for a given path (file or directory).
# Arguments:
#   $1 - Path (file or directory)
# Returns:
#   String
git_timestamp() {
    local -r object_path="${1:?path to object argument required}"
    git_execute --no-pager log -1 --pretty=tformat:"%ct" "${object_path}"
}

########################
# Returns source branch for a given  path (file or directory).
# Arguments:
#   $1 - Path (file or directory)
# Returns:
#   String
git_branch() {
    local -r object_path="${1:?path to object argument required}"
    directory="${object_path}"
    # If argument is a file, pick parent directory.
    if [ -f "${object_path}" ]; then
        directory=$(dirname "${object_path}")
    fi
    git_execute -C "${directory}" rev-parse --abbrev-ref HEAD
}

########################
# Execute an arbitrary git command
# Arguments:
#   $@ - Command to execute
# Returns:
#   String
git_execute() {
    local -r args=("$@")
    local exec
    exec=$(command -v git)

    "${exec}" "${args[@]}"
}