# Copyright 2019 Adevinta

FROM alpine
RUN apk add --no-cache ca-certificates
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-certinfo /vulcan-certinfo
CMD ["/vulcan-certinfo"]
