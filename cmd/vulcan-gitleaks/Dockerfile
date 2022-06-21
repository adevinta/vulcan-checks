# Copyright 2019 Adevinta

FROM zricethezav/gitleaks

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]


# Install check
COPY --chown=gitleaks vulcan-gitleaks /vulcan-gitleaks

CMD ["/vulcan-gitleaks"]
