FROM securego/gosec:2.14.0

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]
WORKDIR /
# Install check

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-gosec /

CMD ["/vulcan-gosec"]
