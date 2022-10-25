# Copyright 2019 Adevinta

FROM alpine
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-exposed-varnish /vulcan-exposed-varnish
CMD ["/vulcan-exposed-varnish"]
