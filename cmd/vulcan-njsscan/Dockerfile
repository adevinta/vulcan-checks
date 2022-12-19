FROM opensecurity/njsscan:0.3.4

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
COPY vulcan-semgrep /vulcan-semgrep

CMD ["/vulcan-semgrep"]
