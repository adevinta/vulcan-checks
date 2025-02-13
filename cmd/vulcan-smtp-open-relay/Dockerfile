# Copyright 2019 Adevinta

FROM alpine
RUN apk add --no-cache nmap nmap-scripts
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-smtp-open-relay /
CMD ["/vulcan-smtp-open-relay"]
