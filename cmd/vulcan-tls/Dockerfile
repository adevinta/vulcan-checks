# Copyright 2019 Adevinta

FROM python:3.11-alpine

WORKDIR /opt/vulcan-tls/cipherscan

# Install Cipherscan.
# Fix silly naming and fix error where "analyze.py" always returns "1" when running with "-j".
# Install dependencies tlslite-ng and python-ecdsa so we don't have to do it in run time.
RUN apk add --no-cache git openssl bash && \
	git clone --depth=1 https://github.com/mozilla/cipherscan . && \
	pip install --upgrade pip && pip install six && \
	sed -i -e 's/fubar/vulnerable/g' -e 's/status = "bad"/status = "vulnerable"/g' -e 's/sys.exit(exit_status)/sys.exit(0)/g' analyze.py && \
	git clone --depth=1 https://github.com/tomato42/tlslite-ng.git .tlslite-ng && \
	ln -s .tlslite-ng/tlslite tlslite && \
	git clone --depth=1 https://github.com/warner/python-ecdsa.git .python-ecdsa && \
	ln -s .python-ecdsa/src/ecdsa ecdsa && \
	apk del git

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-tls /
CMD ["/vulcan-tls"]
