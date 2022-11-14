# Copyright 2019 Adevinta

FROM alpine/git as git

WORKDIR /wrk
RUN git clone --depth=1 https://github.com/zaproxy/zaproxy

# Copied from https://github.com/zaproxy/zaproxy/blob/main/docker/Dockerfile-bare
# This dockerfile builds the zap bare release
FROM debian:unstable-slim AS builder

RUN apt-get update && apt-get install -q -y --fix-missing \
	wget \
	curl \
	openjdk-11-jdk \
	xmlstarlet \
	unzip && \
	apt-get clean

WORKDIR /zap

# Download and expand the latest stable release
RUN wget -qO- https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml | xmlstarlet sel -t -v //url |grep -i Linux | wget --content-disposition -i - -O - | tar zxv && \
	mv ZAP*/* . && \
	rm -R ZAP*

# Update add-ons
RUN ./zap.sh -cmd -silent -addonupdate
# Copy them to installation directory
RUN cp /root/.ZAP/plugin/*.zap plugin/ || :

FROM eclipse-temurin:11-jre
LABEL maintainer="psiinon@gmail.com"

RUN apt update && apt install bash curl

USER root

WORKDIR /zap
COPY --from=builder /zap .
COPY --from=git /wrk/zaproxy/docker/policies /home/zap/.ZAP/policies/

RUN echo "zap2docker-bare" > /zap/container

RUN adduser --home /home/zap --shell /bin/bash --no-create-home --gecos '' --disabled-password zap && \
    rm -rf /var/cache/apk/* && \
    chown zap /zap && \
    chgrp zap /zap && \
    chown -R zap:zap /zap && \
    chown -R zap:zap /home/zap/ && \
    chown -R zap:zap /home/zap/.ZAP/

#Change to the zap user so things get done as the right person (apart from copy)
USER zap

ENV PATH $JAVA_HOME/bin:/zap/:$PATH
ENV ZAP_PATH /zap/zap.sh
ENV HOME /home/zap/
ENV ZAP_PORT 8080
# END Copied

USER root
RUN chown -R zap /zap/

USER zap
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-zap /
CMD ["/vulcan-zap"]
