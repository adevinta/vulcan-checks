# Copyright 2019 Adevinta

FROM alpine
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-heartbleed /vulcan-heartbleed
CMD ["/vulcan-heartbleed"]
