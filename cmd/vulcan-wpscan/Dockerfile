# Copyright 2021 Adevinta

FROM wpscanteam/wpscan

# Override entrypoint
ENTRYPOINT ["/usr/bin/env"]

# Install check
COPY vulcan-wpscan /vulcan-wpscan
CMD ["/vulcan-wpscan"]
