# Copyright 2020 Adevinta

FROM aquasec/trivy:0.41.0

# Required for scanning RHEL/CentOS images
RUN apk add rpm

RUN trivy --quiet image --download-db-only && \
    trivy --quiet image --download-java-db-only && \
    find /root/.cache -name "*.db" -print -exec gzip {} \;

WORKDIR /

ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-trivy /
COPY entrypoint.sh /
COPY config/secret.yaml /
CMD ["/entrypoint.sh"]
ENTRYPOINT []
