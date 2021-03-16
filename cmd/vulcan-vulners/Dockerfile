# Copyright 2020 Adevinta

FROM alpine
RUN apk update && apk add --no-cache nmap nmap-scripts
ADD vulcan-vulners /vulcan-vulners
CMD ["/vulcan-vulners"]
