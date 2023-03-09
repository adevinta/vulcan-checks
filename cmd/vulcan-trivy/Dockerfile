# Copyright 2020 Adevinta

FROM aquasec/trivy:0.38.1

# Required for scanning RHEL/CentOS images
RUN apk add rpm

RUN trivy --quiet image --download-db-only && \
    trivy --quiet image --download-java-db-only && \
    tar cvzf /root/cache.tgz -C /root .cache && \
    rm -rf /root/.cache

WORKDIR /

ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-trivy /
COPY entrypoint.sh /
COPY config/secret.yaml /
CMD ["/entrypoint.sh"]
ENTRYPOINT []
