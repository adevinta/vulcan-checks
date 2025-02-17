# Copyright 2020 Adevinta

FROM alpine
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-github-alerts /
CMD ["/vulcan-github-alerts"]
