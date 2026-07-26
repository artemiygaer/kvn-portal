FROM python:3.13-alpine

RUN apk add --no-cache \
      coreutils \
      curl \
      docker-cli \
      docker-cli-compose \
      openssl \
      procps \
      libqrencode-tools \
    && printf '#!/bin/sh\nexit 3\n' > /usr/local/bin/systemctl \
    && printf '#!/bin/sh\nexit 127\n' > /usr/local/bin/awg \
    && printf '#!/bin/sh\nexit 127\n' > /usr/local/bin/wg \
    && chmod 0755 /usr/local/bin/systemctl /usr/local/bin/awg /usr/local/bin/wg

WORKDIR /project
