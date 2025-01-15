# Copyright 2019 Adevinta

FROM alpine
RUN apk update && apk add nmap nmap-scripts ca-certificates && rm -rf /var/cache/apk/*
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-host-discovery /
CMD ["/vulcan-host-discovery"]
