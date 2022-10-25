# Copyright 2019 Adevinta

FROM alpine
RUN apk update && apk add nmap nmap-scripts && rm -rf /var/cache/apk/*
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-exposed-hdfs /vulcan-exposed-hdfs
CMD ["/vulcan-exposed-hdfs"]
