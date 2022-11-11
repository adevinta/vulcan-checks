# When updating version make sure to check on semgrepignore file as well
ARG SCANNER_VERSION=0.121.2
FROM python:3.11-alpine

ARG SCANNER_VERSION
ENV SCANNER_VERSION ${SCANNER_VERSION}

RUN apk add --no-cache git && \
    pip install ruamel.yaml==0.16.11 semgrep==$SCANNER_VERSION

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-semgrep /

CMD ["/vulcan-semgrep"]
