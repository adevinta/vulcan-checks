# Copyright 2019 Adevinta

FROM alpine
RUN apk update && apk add \
	git \
	gcc \
	make \
	libpcap-dev \
	libc-dev \
	linux-headers \
	&& rm -rf /var/cache/apk/*
RUN git clone https://github.com/robertdavidgraham/masscan
WORKDIR ./masscan
RUN make -j
RUN cp -a ./bin/masscan /usr/local/bin
ADD vulcan-masscan /vulcan-masscan
CMD ["/vulcan-masscan"]
