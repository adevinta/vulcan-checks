# Copyright 2019 Adevinta

FROM alpine

RUN apk add --no-cache ca-certificates
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-aws-trusted-advisor /
CMD ["/vulcan-aws-trusted-advisor"]
