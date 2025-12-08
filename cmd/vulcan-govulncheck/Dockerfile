# Copyright 2024 Adevinta

FROM golang:1.25.5-alpine3.21
ENV GOVULNCHECK_VERSION=v1.1.4
ARG TARGETOS
ARG TARGETARCH
RUN go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}
COPY ${TARGETOS}/${TARGETARCH}/vulcan-govulncheck /usr/bin/vulcan-govulncheck
ENTRYPOINT ["vulcan-govulncheck"]
