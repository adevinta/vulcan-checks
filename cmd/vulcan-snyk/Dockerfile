FROM alpine
RUN apk add --update npm && ls
RUN apk add libstdc++  && ls
RUN npm install -g snyk && ls
ADD vulcan-snyk /vulcan-snyk
CMD ["/vulcan-snyk"]
