FROM owasp/zap2docker-weekly:w2020-08-03

USER root
RUN chown -R zap /zap/

USER zap
ADD vulcan-zap /vulcan-zap
CMD ["/vulcan-zap"]
