FROM node:11-alpine
RUN apk add --update npm curl
RUN apk add libstdc++
RUN npm install -g snyk 
ADD vulcan-snyk /vulcan-snyk
CMD ["/vulcan-snyk"]
