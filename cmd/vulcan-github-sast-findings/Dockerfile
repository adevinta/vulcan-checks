# Copyright 2023 Schibsted

FROM alpine
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-github-sast-findings /
CMD ["/vulcan-github-sast-findings"]
