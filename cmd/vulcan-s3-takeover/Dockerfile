# Copyright 2019 Adevinta

FROM alpine
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-s3-takeover /vulcan-s3-takeover
CMD ["/vulcan-s3-takeover"]
