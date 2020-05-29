FROM golang:1.13.4-alpine as binary_builder

WORKDIR /

COPY go.mod .
COPY go.sum .
RUN go mod download

RUN apk add --no-cache --virtual .build-deps gcc musl-dev libc6-compat

COPY main.go .

RUN GOOS=linux CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' .

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
COPY --from=binary_builder /vulcan-trivy /
COPY entrypoint.sh /
CMD ["/entrypoint.sh"]
