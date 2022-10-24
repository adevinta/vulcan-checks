# Copyright 2022 Adevinta

FROM projectdiscovery/nuclei:latest
ENTRYPOINT []

WORKDIR /
RUN nuclei -update-templates
ADD /vulcan-nuclei .
CMD ["/vulcan-nuclei"]
