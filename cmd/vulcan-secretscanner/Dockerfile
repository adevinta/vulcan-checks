FROM golang:alpine as build

RUN apk update && apk add git alpine-sdk hyperscan-dev
RUN go get github.com/deepfence/SecretScanner

FROM alpine

RUN apk update && apk add skopeo hyperscan bash jq

ADD https://raw.githubusercontent.com/deepfence/SecretScanner/master/config.yaml /ss/config.yaml
ADD ./scan.sh /ss

COPY --from=build /go/bin/SecretScanner /ss

ENTRYPOINT ["/ss/scan.sh"]
