# Copyright 2019 Adevinta

FROM ruby:3.4-alpine

RUN apk add --no-cache openssh build-base \
        && gem install ssh_scan && gem cleanup \
        && apk del build-base

COPY policy /policy

ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-exposed-ssh /
CMD ["/vulcan-exposed-ssh"]
