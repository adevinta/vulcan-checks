FROM python:3.6.4-slim-stretch

# Should be better to join these RUN's by using '&&' but, because a dirty error in the docker version of travis
# this fails.
RUN apt-get update
RUN apt-get install -y --fix-missing git build-essential
RUN apt-get autoremove
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/vulcan-http-headers
WORKDIR /opt/

# Install the HTTP Observatory
RUN git clone https://github.com/mozilla/http-observatory
WORKDIR /opt/http-observatory
RUN git reset --hard e3ef44d9ef3a0d6147b55934e81bd67fd7e2bd7e
RUN pip3 install --upgrade .
RUN pip3 install --upgrade -r requirements.txt

ENV PYTHONPATH $PYTHONPATH:/opt/http-observatory

WORKDIR /opt/vulcan-http-headers

# Install check
COPY vulcan-http-headers /opt/vulcan-http-headers
CMD ["/opt/vulcan-http-headers/vulcan-http-headers"]
