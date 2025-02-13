# Copyright 2019 Adevinta

FROM alpine as builder

WORKDIR /masscan
RUN apk add --no-cache git gcc make linux-headers libc-dev
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan .
RUN make -j

FROM alpine
RUN apk add --no-cache libpcap-dev
COPY --from=builder /masscan/bin/masscan /usr/local/bin
ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-masscan /
CMD ["/vulcan-masscan"]
