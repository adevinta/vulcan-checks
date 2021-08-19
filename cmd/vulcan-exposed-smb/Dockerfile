# Copyright 2021 Adevinta

FROM alpine
RUN apk update && apk add nmap nmap-scripts && rm -rf /var/cache/apk/*
ADD vulcan-exposed-smb /vulcan-exposed-smb
CMD ["/vulcan-exposed-smb"]
