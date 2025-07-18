# Copyright 2025 Adevinta

FROM alpine
RUN apk add --no-cache ca-certificates
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-aws-waf /
CMD ["/vulcan-aws-waf"]
