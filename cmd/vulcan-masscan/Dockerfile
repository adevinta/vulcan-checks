# Copyright 2019 Adevinta

FROM alpine as builder

WORKDIR /masscan
RUN apk update && apk add git gcc make linux-headers libc-dev
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan .
RUN make -j

FROM alpine
RUN apk update && apk add libpcap-dev
COPY --from=builder /masscan/bin/masscan /usr/local/bin
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-masscan /
CMD ["/vulcan-masscan"]
