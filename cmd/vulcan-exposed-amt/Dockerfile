# Copyright 2019 Adevinta

FROM alpine
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-exposed-amt /vulcan-exposed-amt
CMD ["/vulcan-exposed-amt"]
