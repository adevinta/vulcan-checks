FROM golang:1.14-alpine as base
WORKDIR /
RUN GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
RUN /go/bin/nuclei -update-templates

FROM alpine
WORKDIR /
COPY --from=base /root/.nuclei-config.json /root/
COPY --from=base /root/nuclei-templates /root/nuclei-templates
COPY --from=base /go/bin/nuclei /
COPY ./vulcan-nuclei .
CMD ["/vulcan-nuclei"]
