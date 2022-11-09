# Copyright 2022 Adevinta

FROM projectdiscovery/nuclei:latest
ENTRYPOINT []

WORKDIR /
RUN nuclei -update-templates
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-nuclei .
CMD ["/vulcan-nuclei"]
