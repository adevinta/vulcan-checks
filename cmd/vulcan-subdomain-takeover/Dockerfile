# Copyright 2024 Adevinta

FROM python:3.13-alpine

RUN pip3 install --no-cache-dir requests cloudflare ghostbuster

ADD https://ip-ranges.amazonaws.com/ip-ranges.json /tmp
RUN cp /tmp/ip-ranges.json /

WORKDIR /

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-subdomain-takeover /
CMD ["/vulcan-subdomain-takeover"]
