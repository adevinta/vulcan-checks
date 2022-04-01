# Copyright 2019 Adevinta

FROM zricethezav/gitleaks

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]


# Install check
COPY vulcan-gitleaks /vulcan-gitleaks
USER root

CMD ["/vulcan-gitleaks"]
