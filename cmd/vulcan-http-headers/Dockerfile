# Copyright 2019 Adevinta

FROM python:3.7-slim

# Should be better to join these RUN's by using '&&' but, because a dirty error in the docker version of travis
# this fails.
RUN apt update
RUN apt install -y --fix-missing git build-essential libpq-dev python3-dev
RUN apt autoremove
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/vulcan-http-headers
WORKDIR /opt/

# Install the HTTP Observatory
RUN git clone https://github.com/mozilla/http-observatory
WORKDIR /opt/http-observatory
RUN git reset --hard ec0e4071d42b4f5bc429d97868d51e247e2caece
RUN pip3 install --upgrade .
RUN pip3 install --upgrade -r requirements.txt

ENV PYTHONPATH $PYTHONPATH:/opt/http-observatory

WORKDIR /opt/vulcan-http-headers

# Install check
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-http-headers /opt/vulcan-http-headers
CMD ["/opt/vulcan-http-headers/vulcan-http-headers"]
