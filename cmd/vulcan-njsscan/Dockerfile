FROM opensecurity/njsscan:0.3.4

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]
WORKDIR /

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-njsscan /

CMD ["/vulcan-njsscan"]
