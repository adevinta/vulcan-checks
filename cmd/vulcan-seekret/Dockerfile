# Copyright 2019 Adevinta

FROM alpine
ARG TARGETOS TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/vulcan-seekret /vulcan-seekret
ADD rules /rules
CMD ["/vulcan-seekret"]
