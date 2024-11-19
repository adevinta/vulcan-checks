# Copyright 2022 Adevinta

FROM alpine
RUN apk add --no-cache ca-certificates

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-tenable /

CMD ["/vulcan-tenable"]
