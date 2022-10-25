# Copyright 2020 Adevinta

FROM alpine
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-github-alerts /vulcan-github-alerts
CMD ["/vulcan-github-alerts"]
