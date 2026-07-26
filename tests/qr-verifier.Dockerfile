FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends zbar-tools \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["zbarimg", "--quiet", "--raw"]
