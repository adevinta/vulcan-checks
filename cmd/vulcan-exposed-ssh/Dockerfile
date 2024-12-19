# Copyright 2019 Adevinta

FROM ruby:3.1-alpine
RUN apk add --update openssh \
    && apk add build-base \
        && gem install ssh_scan && gem cleanup \
        && apk del build-base
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-exposed-ssh /
ADD policy /policy
CMD ["/vulcan-exposed-ssh"]
