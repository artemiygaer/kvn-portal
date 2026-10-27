FROM kvn-portal-upgrade-e2e-host:latest
RUN apt-get update && apt-get install -y --no-install-recommends mc htop \
    && rm -rf /var/lib/apt/lists/*
COPY wheels /wheels
RUN python3 -m pip install --break-system-packages --no-index --find-links=/wheels \
    flask-sock==0.7.0 simple-websocket==1.1.0 wsproto==1.3.2 h11==0.16.0 gunicorn==26.0.0 \
    && rm -rf /wheels
