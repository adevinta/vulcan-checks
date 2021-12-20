# Copyright 2021 Adevinta
FROM python:slim-buster

RUN apt-get update && \
    apt-get install -y --fix-missing git build-essential && \
    apt-get autoremove && \
    rm -rf /var/lib/apt/lists/
RUN echo hello
RUN git clone https://github.com/manelmontilla/log4j-scan.git --single-branch

WORKDIR /log4j-scan
RUN pip install -r requirements.txt
ADD vulcan-log4shell .
CMD ["/log4j-scan/vulcan-log4shell"]
