# Copyright 2019 Adevinta

FROM softwaresecurityproject/zap-bare:2.15.0
USER root
RUN chown -R zap /zap/

USER zap

RUN /zap/zap.sh -cmd -addonupdate -notel

ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-zap /
CMD ["/vulcan-zap"]
