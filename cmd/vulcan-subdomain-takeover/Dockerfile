# Copyright 2025 Adevinta

FROM alpine
RUN apk add --no-cache ca-certificates

ADD https://ip-ranges.amazonaws.com/ip-ranges.json /tmp
RUN cp /tmp/ip-ranges.json /

WORKDIR /

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-subdomain-takeover /
CMD ["/vulcan-subdomain-takeover"]
