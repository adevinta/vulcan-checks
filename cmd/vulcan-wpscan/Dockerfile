# Copyright 2019 Adevinta

FROM wpscanteam/wpscan

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-wpscan /
CMD ["/vulcan-wpscan"]
