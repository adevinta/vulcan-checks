# Copyright 2022 Adevinta

FROM projectdiscovery/nuclei:v3.4.2
ENTRYPOINT []

WORKDIR /
RUN nuclei -v -update-templates
COPY templates /root/nuclei-templates
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-nuclei .
CMD ["/vulcan-nuclei"]
