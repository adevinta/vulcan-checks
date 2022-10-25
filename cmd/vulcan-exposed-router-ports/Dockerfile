# Copyright 2019 Adevinta

FROM alpine
RUN apk update && apk add nmap nmap-scripts && rm -rf /var/cache/apk/*
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-exposed-router-ports /vulcan-exposed-router-ports
CMD ["/vulcan-exposed-router-ports"]
