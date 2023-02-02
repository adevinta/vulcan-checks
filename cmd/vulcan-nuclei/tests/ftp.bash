#!/usr/bin/env bash

# Copyright 2023 Adevinta

IMAGE_TAG=vulcan_test_ftp_server
TEST_SERVER_DOCKERFILE=test_ftpd_dockerfile
CONTAINER_NAME="test_ftp_server-$(echo $RANDOM | md5sum | head -c 20)"

docker build --tag $IMAGE_TAG --file $TEST_SERVER_DOCKERFILE .
docker run --rm -d --name $CONTAINER_NAME -p 21:21 $IMAGE_TAG
echo $CONTAINER_NAME
read -p "Press any key to kill the test container..."
docker kill $CONTAINER_NAME
