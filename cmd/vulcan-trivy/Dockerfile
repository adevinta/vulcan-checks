FROM aquasec/trivy:0.5.2 as dependency_builder

ARG TRIVY_CACHE_DIR=trivy_cache

RUN mkdir $TRIVY_CACHE_DIR && \
    trivy --quiet --download-db-only --cache-dir $TRIVY_CACHE_DIR/ && \
    tar cvfz trivy_cache.tgz $TRIVY_CACHE_DIR

FROM alpine
# Required for scanning RHEL/CentOS images
RUN apk add rpm
WORKDIR /
COPY --from=dependency_builder /usr/local/bin/trivy trivy_cache.tgz /
COPY ./vulcan-trivy /
COPY entrypoint.sh /
CMD ["/entrypoint.sh"]
