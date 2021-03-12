# Copyright 2021 Adevinta

FROM alpine
RUN apk update && apk add nmap nmap-scripts && rm -rf /var/cache/apk/*
ADD vulcan-smtp-open-relay /vulcan-smtp-open-relay
CMD ["/vulcan-smtp-open-relay"]
