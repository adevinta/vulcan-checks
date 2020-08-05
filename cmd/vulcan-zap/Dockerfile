FROM owasp/zap2docker-weekly

USER root
RUN chown -R zap /zap/

USER zap
ADD vulcan-zap /vulcan-zap
CMD ["/vulcan-zap"]
