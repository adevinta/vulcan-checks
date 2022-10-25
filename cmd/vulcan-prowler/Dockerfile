# Copyright 2020 Adevinta

FROM toniblyx/prowler

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Copy CIS controls info file
COPY cis_controls.json cis_controls.json

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-prowler /vulcan-prowler

CMD ["/vulcan-prowler"]
