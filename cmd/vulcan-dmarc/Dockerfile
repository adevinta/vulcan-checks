# Copyright 2019 Adevinta

FROM alpine
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-dmarc /
CMD ["/vulcan-dmarc"]
