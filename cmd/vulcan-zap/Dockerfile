# Copyright 2019 Adevinta

FROM zaproxy/zap-bare:2.16.1

USER root
RUN chown -R zap /zap/

USER zap

RUN /zap/zap.sh -cmd -addonupdate -notel

ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-zap /
CMD ["/vulcan-zap"]
