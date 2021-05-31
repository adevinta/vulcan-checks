# Copyright 2019 Adevinta

FROM ruby:2.4-alpine
RUN apk add --update openssh \
    && apk add build-base \
        && gem install ssh_scan && gem cleanup \
        && apk del build-base
ADD vulcan-exposed-ssh /vulcan-exposed-ssh
ADD policy /policy
CMD ["/vulcan-exposed-ssh"]
