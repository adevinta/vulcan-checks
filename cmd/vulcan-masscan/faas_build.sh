#!/bin/bash

apk update && apk add \
	git \
	gcc \
	make \
	libpcap-dev \
	libc-dev \
	linux-headers \
	&& rm -rf /var/cache/apk/*

git clone https://github.com/robertdavidgraham/masscan && \
    cd ./masscan && \
    make -j && \
    cp -av ./bin/masscan /usr/local/bin && \
	cd .. && rm -rf ./masscan
