FROM debian:stretch-slim

RUN apt-get update && \
	apt-get install -y bash python python-six git && \
	apt-get autoremove && \
	rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/vulcan-tls
WORKDIR /opt/vulcan-tls

# Install Cipherscan.
RUN git clone https://github.com/mozilla/cipherscan
WORKDIR /opt/vulcan-tls/cipherscan

# Fix problem where cipherscan reports good certs as bad
RUN git fetch origin pull/184/head:analyze-inter
RUN git cherry-pick -n 0c6f41ddc6063ceb457de2046dca19cbf6673c5a

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

# Install check
COPY vulcan-tls /vulcan-tls
CMD ["/vulcan-tls"]
