FROM debian:stretch-slim
# Should be better to join these RUN's by using '&&' but, because a dity error in the docker version of travis
# this fails.
RUN apt-get update
RUN apt-get install -y bash python python-six git build-essential perl zlib1g-dev curl
RUN apt-get autoremove
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/vulcan-tls
WORKDIR /opt/vulcan-tls

# Install required OpenSSL fork.
RUN git clone https://github.com/PeterMosmans/openssl.git --depth 1 -b 1.0.2-chacha
WORKDIR /opt/vulcan-tls/openssl
RUN ./Configure zlib no-shared experimental-jpake enable-md2 \
enable-rc5 enable-rfc3779 enable-gost enable-static-engine linux-x86_64
RUN make depend
RUN make
RUN make report
RUN cp ./apps/openssl /opt/openssl

WORKDIR /opt/vulcan-tls

# Install Cipherscan.
RUN git clone https://github.com/mozilla/cipherscan
WORKDIR /opt/vulcan-tls/cipherscan

# Fix silly naming.
RUN sed -i 's/fubar/vulnerable/g' analyze.py
RUN sed -i 's/status = "bad"/status = "vulnerable"/g' analyze.py

# TODO: Do this properly by forking and fixing Cipherscan.
# Fix error where "analyze.py" always returns "1" when running with "-j".
RUN sed -i 's/sys.exit(exit_status)/sys.exit(0)/g' analyze.py

# Install dependencies so we don't have to do it in run time.
RUN git clone --depth=1 https://github.com/tomato42/tlslite-ng.git .tlslite-ng && \
ln -s .tlslite-ng/tlslite tlslite
RUN git clone --depth=1 https://github.com/warner/python-ecdsa.git .python-ecdsa && \
ln -s .python-ecdsa/src/ecdsa ecdsa

# Set new OpenSSL path with priority.
RUN export PATH=/opt/vulcan-tls/openssl/apps:$PATH

# Install check
COPY vulcan-tls /vulcan-tls
CMD ["/vulcan-tls"]


