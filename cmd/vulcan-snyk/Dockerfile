FROM alpine
RUN apk add --update npm
RUN apk add libstdc++ 
RUN npm install -g snyk
ADD vulcan-snyk /vulcan-snyk
CMD ["/vulcan-snyk"]
