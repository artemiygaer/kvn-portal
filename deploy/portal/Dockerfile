# Multi-arch index python:3.13-alpine, linux/amd64 manifest проверяется release-builder.
FROM python:3.13-alpine@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 AS base

ARG KVN_BUILD_ID=20260726-121316
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    KVN_BUILD_ID=${KVN_BUILD_ID}

RUN addgroup -g 10001 -S kvn \
    && adduser -u 10001 -S -D -H -G kvn kvn

WORKDIR /app
COPY requirements.txt ./
COPY wheels ./wheels
RUN cd /app/wheels \
    && sha256sum -c SHA256SUMS \
    && cd /app \
    && pip install --no-cache-dir --no-index --find-links=/app/wheels -r requirements.txt \
    && rm -rf /app/wheels

COPY app ./app
COPY agent_client.py agent_protocol.py ./
COPY wsgi.py ./wsgi.py
RUN mkdir -p /data \
    && chown -R kvn:kvn /data /app

FROM base AS runtime
USER 10001:10001
EXPOSE 8080
CMD ["sh", "-c", "exec gunicorn --bind=0.0.0.0:8080 --workers=${KVN_PORTAL_WORKERS:-1} --threads=${KVN_PORTAL_THREADS:-2} --timeout=${KVN_PORTAL_TIMEOUT:-1800} --keep-alive=${KVN_PORTAL_KEEPALIVE:-5} --max-requests=${KVN_PORTAL_MAX_REQUESTS:-600} --max-requests-jitter=${KVN_PORTAL_MAX_REQUESTS_JITTER:-60} --access-logfile=- --error-logfile=- 'app:create_app()'"]

FROM base AS test
COPY tests ./tests
RUN python -m unittest discover -s tests -v
