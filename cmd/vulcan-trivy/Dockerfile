# Copyright 2020 Adevinta

FROM aquasec/trivy:0.40.0 as dependency_builder

ENV TRIVY_CACHE_DIR=/trivy_cache

RUN mkdir $TRIVY_CACHE_DIR && \
    trivy --quiet image --download-db-only && \
    tar cvfz trivy_cache.tgz ${TRIVY_CACHE_DIR}

FROM alpine

# Required for scanning RHEL/CentOS images
RUN apk add rpm
WORKDIR /
ENV TRIVY_CACHE_DIR=/trivy_cache
COPY --from=dependency_builder /usr/local/bin/trivy trivy_cache.tgz /
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-trivy /
COPY entrypoint.sh /
CMD ["/entrypoint.sh"]
