FROM alpine
RUN apk update && apk add nmap nmap-scripts && rm -rf /var/cache/apk/*
ADD vulcan-exposed-ftp /vulcan-exposed-ftp
CMD ["/vulcan-exposed-ftp"]
