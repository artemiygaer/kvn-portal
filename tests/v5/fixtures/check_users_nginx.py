"""Проверка маршрутов карточки на настоящем nginx в изолированном Docker."""

import re
import subprocess

from v5.core.tls.gateway import _portal_proxy


def response_codes(routes):
    config = """
pid /tmp/kvn-test-nginx.pid;
error_log stderr crit;
events {}
http {
    access_log off;
    limit_req_zone $binary_remote_addr zone=kvn_sub_ip:1m rate=15r/m;
    limit_req_zone $binary_remote_addr zone=kvn_sub_global:1m rate=60r/m;
    upstream portal { server 127.0.0.1:18081; }
    server {
        listen 127.0.0.1:18081;
        location = /users { return 303 /login; }
        location / { return 200 "portal"; }
    }
    server {
        listen 127.0.0.1:18080;
""" + routes + "    }\n}\n"
    command = (
        "tee /tmp/kvn-test-nginx.conf >/dev/null; nginx -c /tmp/kvn-test-nginx.conf; "
        "for path in /users /users/example/profiles.txt /users/example/grant; do "
        "wget -S -O /dev/null \"http://127.0.0.1:18080$path\" 2>&1 | "
        "awk '/HTTP\\/1\\.[01] / {print $2; exit}'; done"
    )
    result = subprocess.run(["docker", "run", "--rm", "--pull=never", "--network", "none", "-i",
                             "--entrypoint", "/bin/sh", "nginx:1.31.8-alpine", "-ec", command],
                            input=config, text=True, capture_output=True, check=True, timeout=35)
    return [int(item) for item in re.findall(r"^[0-9]{3}$", result.stdout, flags=re.MULTILINE)]


if __name__ == "__main__":
    current = _portal_proxy("$http_host")
    old = current.replace('location ~ "^/users/"', "location /users/")
    assert response_codes(old) == [301, 200, 200], "Не воспроизвели перенаправление nginx"
    assert response_codes(current) == [303, 200, 200], "Не сохранились маршруты входа, экспорта или применения"
    print("nginx: старый /users возвращал 301; новый передаёт 303 от портала, экспорт и grant доступны upstream.")
