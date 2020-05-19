#!/bin/bash
#
# Docker library

########################
# Load global variables used on Docker configuration
# Globals:
#   DKR_*
# Arguments:
#   None
# Returns:
#   Series of exports to be used as 'eval' arguments
#########################
dkr_env() {
    cat <<"EOF"
export DKR_AUTHENTICATED_REGISTRY=${DKR_AUTHENTICATED_REGISTRY:-true}
export DKR_USERNAME=${DKR_USERNAME:-}
export DKR_PASSWORD=${DKR_PASSWORD:-}
export DKR_SERVER=${DKR_SERVER:-docker.io}
export DKR_REGISTRY=${DKR_REGISTRY:-https://registry.hub.docker.com}
export DKR_REGISTRY_VERSION=${DKR_REGISTRY_VERSION:-v2}
export DKR_PRINT_LOGS=${DKR_PRINT_LOGS:-false}
EOF
}

########################
# Login to target registry.
# Arguments:
#   None
# Returns:
#   None
dkr_login() {
    if [[ $DKR_AUTHENTICATED_REGISTRY == true ]]; then
        local -r username="${DKR_USERNAME:?docker username required}"
        local -r password="${DKR_PASSWORD:?docker password required}"
        local -r server="${DKR_SERVER:?docker server required}"

        echo "${password}" | dkr_execute login -u "${username}" --password-stdin "${server}"
    fi
}

########################
# Check if docker image and tag exists in target registry.
# Arguments:
#   $1 - Docker image name
#   $2 - Docker image tag (Optional. Default: latest)
# Returns:
#   Boolean
dkr_image_exists() {
    local -r image_name="${1:?docker image name argument required}"
    local -r tag="${2:-latest}"
    local -r url="$DKR_REGISTRY/$DKR_REGISTRY_VERSION/repositories/$DKR_USERNAME/$image_name/tags/$tag"

    http_response=$(curl_execute "$url")
    # extract the status
    http_status=$(echo "$http_response" | tr -d '\n' | sed -e 's/.*HTTPSTATUS://')

    if [ "$http_status" -eq 200 ]; then
        echo true
        return
    fi
    echo false
}

########################
# Check if docker image and tag exists locally.
# Arguments:
#   $1 - Docker image name
#   $2 - Docker image tag (Optional. Default: latest)
# Returns:
#   Boolean
dkr_local_image_exists() {
    local -r image_name="${1:?docker image name argument required}"
    local -r tag="${2:-latest}"
    local -r image_with_tag="$DKR_USERNAME/$image_name:$tag"

    image_id=$(dkr_execute images -q "$image_with_tag")

    if [ -z "$image_id" ]; then
        echo false
        return
    fi
    echo true
}

########################
# Build Dockerfile image.
# Arguments:
#   $1 - Build context path
#   $2 - Docker image name
# Returns:
#   None
dkr_build() {
    local -r context="${1:?docker build context path is required}"
    local -r image_name="${2:?docker image name argument required}"

    if [ ! -d "$context" ]; then
        echo "Context path provided [$context] does not exist or is not a directory" 1>&2
        exit 1
    fi
    cd "$context" || exit
    if [[ $DKR_PRINT_LOGS == true ]]; then
        dkr_execute build -t "$DKR_USERNAME/$image_name" .
    else
        dkr_execute build --quiet -t "$DKR_USERNAME/$image_name" . > /dev/null
    fi
    cd - > /dev/null || return
}

########################
# Add tags to docker image.
# Arguments:
#   $1 - Docker image name
#   $@ - List of tags to apply to the image
# Returns:
#   None
dkr_tag() {
    local -r image_name="${1:?docker image name argument required}"
    shift
    read -r -a tags <<< "$(tr ',;' ' ' <<< "$@")"

    if ! dkr_execute image inspect "$DKR_USERNAME/$image_name" > /dev/null; then
        echo "Docker image [$DKR_USERNAME/$image_name] does not exist" 1>&2
        exit 1
    fi

    for t in "${tags[@]}"; do
        dkr_execute tag "$DKR_USERNAME/$image_name" "$DKR_USERNAME/$image_name:$t"
    done
}

########################
# Push docker image to registry.
# Arguments:
#   $1 - Docker image name
# Returns:
#   String
dkr_push() {
    local -r image_name="${1:?docker image name argument required}"

    if ! dkr_execute image inspect "$DKR_USERNAME/$image_name" > /dev/null; then
        echo "Docker image [$DKR_USERNAME/$image_name] does not exist" 1>&2
        exit 1
    fi
    # Ensure we are logged in
    dkr_login > /dev/null
    dkr_execute push "$DKR_USERNAME/$image_name" > /dev/null
}

########################
# Execute an arbitrary docker command
# Arguments:
#   $@ - Command to execute
# Returns:
#   String
dkr_execute() {
    local -r args=("$@")
    local exec
    exec=$(command -v docker)

    "${exec}" "${args[@]}"
}

########################
# Execute curl to provided url.
# Arguments:
#   $1 - Target url
# Returns:
#   String
curl_execute() {
    local -r url="${1:?url is required}"
    curl -L --silent --write-out "HTTPSTATUS:%{http_code}" "$url"
}