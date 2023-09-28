# Copyright 2019 Adevinta

FROM owasp/zap2docker-bare:2.13.0
USER root
RUN chown -R zap /zap/

USER zap

RUN /zap/zap.sh -cmd -addonupdate -notel

ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-zap /
CMD ["/vulcan-zap"]
