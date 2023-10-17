# Copyright 2020 Adevinta

FROM toniblyx/prowler:3.10.0

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-prowler /

CMD ["/vulcan-prowler"]
