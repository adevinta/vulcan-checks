# Copyright 2020 Adevinta

FROM aquasec/trivy:0.66.0

# Required for scanning RHEL/CentOS images
RUN apk add --no-cache rpm && \
    trivy --quiet image --download-db-only --db-repository public.ecr.aws/aquasecurity/trivy-db && \
    trivy --quiet image --download-java-db-only  --java-db-repository public.ecr.aws/aquasecurity/trivy-java-db


# Skip as it's time consuming to unzip and increases the size of the container (not the image)
# RUN find /root/.cache -name "*.db" -print -exec gzip {} \;

WORKDIR /

ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-trivy /
COPY entrypoint.sh /
COPY config/secret.yaml /
CMD ["/entrypoint.sh"]
ENTRYPOINT []
