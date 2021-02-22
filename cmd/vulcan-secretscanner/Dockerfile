FROM deepfenceio/secretscanning:latest as SecretScanner

FROM ubuntu:focal

RUN apt-get update && apt-get install -y libhyperscan5 curl gnupg jq

RUN . /etc/os-release && sh -c "echo 'deb https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/ /' > /etc/apt/sources.list.d/devel:kubic:libcontainers:stable.list" \
    && curl -L https://download.opensuse.org/repositories/devel:/kubic:/libcontainers:/stable/xUbuntu_${VERSION_ID}/Release.key | apt-key add - \
    && apt update && apt install -y skopeo

COPY --from=SecretScanner /home/deepfence/src/SecretScanner/SecretScanner /ss/SecretScanner
COPY --from=SecretScanner /home/deepfence/src/SecretScanner/config.yaml /ss/config.yaml

ADD ./scan.sh /ss

ENTRYPOINT ["/ss/scan.sh"]
