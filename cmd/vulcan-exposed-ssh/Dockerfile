FROM ruby:2.4-alpine
RUN apk update && apk add openssh && gem install ssh_scan
ADD vulcan-exposed-ssh /vulcan-exposed-ssh
ADD policy /policy
CMD ["/vulcan-exposed-ssh"]
