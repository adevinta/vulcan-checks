FROM returntocorp/semgrep:0.116.0

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
COPY vulcan-semgrep /vulcan-semgrep

CMD ["/vulcan-semgrep"]
