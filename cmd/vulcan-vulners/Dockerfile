# Copyright 2020 Adevinta

FROM alpine
RUN apk add --no-cache nmap nmap-scripts
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-vulners /
CMD ["/vulcan-vulners"]
