# Copyright 2020 Adevinta

FROM toniblyx/prowler:2.12.1

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Copy CIS controls info file
COPY cis_controls.json cis_controls.json

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-prowler /

CMD ["/vulcan-prowler"]
