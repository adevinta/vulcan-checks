# Copyright 2019 Adevinta

FROM python:3.9-alpine

COPY setup.py /

WORKDIR /opt/http-observatory

RUN apk --no-cache add --virtual mydeps git build-base linux-headers && \
    git clone https://github.com/mozilla/http-observatory . && \
    git reset --hard 6ac246ad72d691fd2d0ac24b8ca8549631d87f7b && \
    mv /setup.py . && \
    pip3 install --no-cache-dir -r httpobs/requirements.txt -r httpobs/scanner/requirements.txt . && \
    rm -rf ./build && \
    apk del mydeps

WORKDIR /

# Install check
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-http-headers /
CMD ["/vulcan-http-headers"]
