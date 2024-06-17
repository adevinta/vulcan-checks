# Copyright 2020 Adevinta

FROM aquasec/trivy:0.52.2

# Required for scanning RHEL/CentOS images
RUN apk add --no-cache rpm && \
    trivy --quiet image --download-db-only && \
    trivy --quiet image --download-java-db-only

# Skip as it's time consuming to unzip and increases the size of the container (not the image)
# RUN find /root/.cache -name "*.db" -print -exec gzip {} \;

WORKDIR /

ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-trivy /
COPY entrypoint.sh /
COPY config/secret.yaml /
CMD ["/entrypoint.sh"]
ENTRYPOINT []
