# Copyright 2019 Adevinta

FROM node:alpine
RUN apk add --no-cache ca-certificates
RUN yarn global add retire
ADD https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json /jsrepository.json
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-retirejs /
CMD ["/vulcan-retirejs"]
