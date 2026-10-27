# Одноразовый Debian userspace для изолированного теста systemd в WSL.
FROM kvn-portal-shell:e2e
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus \
    && rm -rf /var/lib/apt/lists/* \
    && printf '[boot]\nsystemd=true\n' > /etc/wsl.conf
