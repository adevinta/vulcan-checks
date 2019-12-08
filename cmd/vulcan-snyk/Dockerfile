FROM alpine
RUN apk add --update nodejs npm
RUN apk add --update npm
RUN npm install -g snyk 
ADD vulcan-snyk /vulcan-snyk
CMD ["/vulcan-snyk"]
