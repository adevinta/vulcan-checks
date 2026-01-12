FROM returntocorp/semgrep:1.146.0

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-semgrep /

CMD ["/vulcan-semgrep"]
