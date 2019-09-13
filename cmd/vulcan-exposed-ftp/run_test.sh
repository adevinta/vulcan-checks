#!/usr/bin/env bash

IMAGE_TAG=test_ftp_server_1abe865ab24f4f45babd845e2fee390a
TEST_SERVER_DOCKERFILE=test_ftpd_dockerfile
CONTAINER_NAME=test_ftp_server-1abe865ab24f4f45babd845e2fee390a
BINARY_NAME=exposed-ftp-1abe865ab24f4f45babd845e2fee390a
SLEEP_TIME=0

# Build docker image
docker build --tag $IMAGE_TAG --file $TEST_SERVER_DOCKERFILE .
# Run docker image
docker run --rm -d --name $CONTAINER_NAME -p 21:21 $IMAGE_TAG
sleep $SLEEP_TIME
# Run scan
go build -o $BINARY_NAME main.go && ./$BINARY_NAME -t && rm $BINARY_NAME
# Stop docker image
docker stop $CONTAINER_NAME
