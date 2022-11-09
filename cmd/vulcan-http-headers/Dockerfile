# Copyright 2019 Adevinta

FROM python:3.8-slim

COPY setup.py /

WORKDIR /opt/http-observatory

RUN apt update && \
    apt install -y --fix-missing build-essential git && \
    git clone https://github.com/mozilla/http-observatory . && \
    git reset --hard 6ac246ad72d691fd2d0ac24b8ca8549631d87f7b && \
    mv /setup.py . && \
    pip3 install --upgrade -r httpobs/requirements.txt -r httpobs/scanner/requirements.txt . && \
    apt autoremove -y build-essential git && \
    rm -rf ./build && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-http-headers /
CMD ["/vulcan-http-headers"]
