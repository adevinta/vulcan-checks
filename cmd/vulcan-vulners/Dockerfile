# Copyright 2020 Adevinta

FROM alpine
RUN apk update && apk add --no-cache nmap nmap-scripts
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-vulners /vulcan-vulners
CMD ["/vulcan-vulners"]
