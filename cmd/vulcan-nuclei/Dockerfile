FROM golang:1.17-alpine as base
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
