FROM returntocorp/semgrep

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
COPY vulcan-semgrep /vulcan-semgrep

CMD ["/vulcan-semgrep"]
