FROM docker:29-cli AS dockercli
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-flask bash curl openssl procps passwd util-linux \
    iproute2 iptables qrencode ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins /usr/local/libexec/docker/cli-plugins
WORKDIR /project
