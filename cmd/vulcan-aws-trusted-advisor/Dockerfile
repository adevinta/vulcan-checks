# Copyright 2019 Adevinta

FROM alpine

RUN apk add --no-cache ca-certificates
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-aws-trusted-advisor /vulcan-aws-trusted-advisor
CMD ["/vulcan-aws-trusted-advisor"]
