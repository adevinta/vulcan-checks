# Copyright 2020 Adevinta

FROM toniblyx/prowler

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Copy CIS controls info file
COPY cis_controls.json cis_controls.json

# Install check
COPY vulcan-prowler /vulcan-prowler

CMD ["/vulcan-prowler"]
