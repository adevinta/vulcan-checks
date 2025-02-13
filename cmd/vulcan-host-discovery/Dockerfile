# Copyright 2019 Adevinta

FROM alpine
RUN apk add --no-cache nmap nmap-scripts ca-certificates
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-host-discovery /
CMD ["/vulcan-host-discovery"]
