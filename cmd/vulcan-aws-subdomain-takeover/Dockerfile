# Copyright 2025 Adevinta

FROM alpine
RUN apk add --no-cache ca-certificates

WORKDIR /
ADD https://ip-ranges.amazonaws.com/ip-ranges.json /

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-aws-subdomain-takeover /
CMD ["/vulcan-aws-subdomain-takeover"]
