FROM ruby:2.4-slim

# Install WPScan
RUN apt-get update && apt-get install -y curl libcurl4 procps sqlite git \
    ruby-dev libffi-dev make gcc musl-dev zlib1g-dev procps libsqlite3-dev && \
    rm -rf /var/lib/apt/lists/*
ARG BUNDLER_ARGS="--jobs=8 --without test development"
RUN addgroup vulcan && adduser --disabled-password --home /opt/vulcan-wpscan/ --gecos "" --ingroup vulcan vulcan
RUN echo "gem: --no-ri --no-rdoc" > /etc/gemrc
RUN git clone https://github.com/wpscanteam/wpscan /opt/vulcan-wpscan/wpscan
RUN chown -R vulcan:vulcan /opt/vulcan-wpscan
WORKDIR /opt/vulcan-wpscan/wpscan
RUN bundle install --system $BUNDLER_ARGS && rake install --trace

# Update WPScan DB
USER vulcan
RUN /usr/local/bundle/bin/wpscan --update --verbose

# Install check
COPY vulcan-wpscan /vulcan-wpscan
CMD ["/vulcan-wpscan"]
