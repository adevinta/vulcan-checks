# Copyright 2019 Adevinta

FROM owasp/zap2docker-stable:latest

USER root
RUN chown -R zap /zap/

USER zap
ADD vulcan-zap /vulcan-zap
CMD ["/vulcan-zap"]
