# Copyright 2023 Schibsted

FROM alpine
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-github-secrets /
CMD ["/vulcan-github-secrets"]
