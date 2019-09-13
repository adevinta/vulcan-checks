FROM alpine
RUN apk update && apk add nmap nmap-scripts && rm -rf /var/cache/apk/*
ADD vulcan-exposed-http /vulcan-exposed-http
CMD ["/vulcan-exposed-http"]
