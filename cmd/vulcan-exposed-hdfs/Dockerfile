FROM alpine
RUN apk update && apk add nmap nmap-scripts && rm -rf /var/cache/apk/*
ADD vulcan-exposed-hdfs /vulcan-exposed-hdfs
CMD ["/vulcan-exposed-hdfs"]
