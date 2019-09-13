FROM alpine
RUN apk update && apk add nmap nmap-scripts && rm -rf /var/cache/apk/*
ADD vulcan-exposed-db /vulcan-exposed-db
CMD ["/vulcan-exposed-db"]
