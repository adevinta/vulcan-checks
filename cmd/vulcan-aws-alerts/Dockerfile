# Copyright 2020 Adevinta

FROM alpine
RUN apk add --no-cache ca-certificates

ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-aws-alerts /
CMD ["/vulcan-aws-alerts"]
