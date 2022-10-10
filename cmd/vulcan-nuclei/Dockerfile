# Copyright 2022 Adevinta

FROM golang:1.19.1-alpine as base
RUN apk add build-base
WORKDIR /
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    nuclei -update-templates

FROM alpine
WORKDIR /
COPY --from=base /root/.config /root/
COPY --from=base /root/nuclei-templates /root/nuclei-templates
COPY --from=base /go/bin/nuclei /
COPY ./vulcan-nuclei .
CMD ["/vulcan-nuclei"]
