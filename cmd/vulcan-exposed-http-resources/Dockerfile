# Copyright 2020 Adevinta

FROM scratch
WORKDIR /
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-exposed-http-resources .
ADD resources.yaml .
CMD ["/vulcan-exposed-http-resources"]
