FROM returntocorp/semgrep:1.77.0

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-semgrep /

CMD ["/vulcan-semgrep"]
