# Copyright 2019 Adevinta

FROM alpine
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-results-load-test /
CMD ["/vulcan-results-load-test"]
