#!/usr/bin/env bash

# Copyright 2023 Adevinta

IMAGE_TAG=test_ftp_server_1abe865ab24f4f45babd845e2fee390a
TEST_SERVER_DOCKERFILE=test_ftpd_dockerfile
CONTAINER_NAME=test_ftp_server-1abe865ab24f4f45babd845e2fee390a

docker build --tag $IMAGE_TAG --file $TEST_SERVER_DOCKERFILE .
docker run --rm -d --name $CONTAINER_NAME -p 21:21 $IMAGE_TAG
read -p "Press any key to stop the container..."
docker stop $CONTAINER_NAME
