# Copyright 2019 Adevinta

FROM node:alpine
RUN apk add --no-cache ca-certificates
RUN npm install -g retire

# Execute in /app to prevent retire to walk trough / and fail.
WORKDIR /app   
ADD https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json /app/jsrepository.json
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-retirejs /app
CMD ["/app/vulcan-retirejs"]
