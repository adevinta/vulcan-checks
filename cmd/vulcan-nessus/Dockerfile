# Copyright 2019 Adevinta

FROM tenableofficial/nessus
# These username and password are required
# but not used nor accessible by any mean.
ENV USERNAME=admin
ENV PASSWORD=admin
ADD vulcan-nessus /vulcan-nessus
ADD start.sh /start.sh
CMD ["/start.sh"]
