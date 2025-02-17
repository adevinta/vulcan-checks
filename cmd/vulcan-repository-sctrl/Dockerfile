# Copyright 2024 Adevinta

FROM semgrep/semgrep:1.97.0-nonroot

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-repository-sctrl /
COPY custom-rules /custom-rules

CMD ["/vulcan-repository-sctrl"]
