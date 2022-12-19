FROM opensecurity/njsscan:0.3.4

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]
WORKDIR /

# Install check
COPY vulcan-njsscan /vulcan-njsscan

CMD ["/vulcan-njsscan"]
