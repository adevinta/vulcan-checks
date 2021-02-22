FROM golang:alpine as build

RUN apk update && apk add git alpine-sdk hyperscan-dev
RUN go get github.com/deepfence/SecretScanner

FROM alpine

RUN apk update && apk add skopeo hyperscan bash jq

ADD config.yaml /app/config.yaml
ADD scan.sh /app

COPY --from=build /go/bin/SecretScanner /usr/bin

ENTRYPOINT ["/app/scan.sh"]
