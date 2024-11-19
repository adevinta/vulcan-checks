# Copyright 2019 Adevinta

FROM ruby:3.4-alpine

RUN apk add --no-cache openssh \
        && apk add build-base \
        && gem install ssh_scan && gem cleanup \
        && apk del build-base \
        && rm -rf /var/cache/apk/*

COPY policy /policy

ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-exposed-ssh /
CMD ["/vulcan-exposed-ssh"]
