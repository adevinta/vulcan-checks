# Copyright 2022 Adevinta

FROM projectdiscovery/nuclei:v2.8.3
ENTRYPOINT []

WORKDIR /
RUN nuclei -update-templates
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-nuclei .
CMD ["/vulcan-nuclei"]
