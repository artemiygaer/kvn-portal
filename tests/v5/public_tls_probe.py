"""Внешняя read-only проверка отдельного стенда; только системные доверенные CA."""

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
from ipaddress import ip_address
import json
from pathlib import Path
import socket
import ssl

from v5.core.tls.identity import TLSIdentity


def _http(address, identity):
    connection = http.client.HTTPConnection(address, 80, timeout=8)
    try:
        connection.request("GET", "/.well-known/acme-challenge/kvn-v5-probe-not-created",
                           headers={"Host": identity.authority, "Connection": "close"})
        response = connection.getresponse()
        if response.status != 404:
            raise RuntimeError(f"HTTP-01: для {identity.name} отсутствующий токен не вернул 404")
    finally:
        connection.close()
    connection = http.client.HTTPConnection(address, 80, timeout=8)
    try:
        connection.request("GET", "/", headers={"Host": identity.authority, "Connection": "close"})
        response = connection.getresponse()
        if response.status != 200 or not response.getheader("Content-Security-Policy"):
            raise RuntimeError(f"HTTP/80: для {identity.name} не подтверждена публичная страница")
    finally:
        connection.close()


def _tls(address, identity, port, path, status, context):
    host = identity.authority if port == 443 else f"{identity.authority}:{port}"
    with socket.create_connection((address, port), timeout=8) as connection:
        with context.wrap_socket(connection, server_hostname=identity.name) as session:
            cert = session.getpeercert()
            der = session.getpeercert(binary_form=True)
            san = cert.get("subjectAltName", ())
            label = "IP Address" if identity.is_ip else "DNS"
            if len(san) != 1 or san[0][0] != label or TLSIdentity(san[0][1], identity.is_ip) != identity:
                raise RuntimeError(f"TLS/{port}: для {identity.name} не подтверждён точный SAN")
            session.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
            with http.client.HTTPResponse(session) as response:
                response.begin()
                if response.status != status:
                    raise RuntimeError(f"HTTPS/{port}: неожиданный статус для {identity.name}: {response.status}")
                if port == 443 and (response.getheader("Set-Cookie") or not response.getheader("Content-Security-Policy")):
                    raise RuntimeError(f"HTTPS/443: изоляция страницы для {identity.name} не подтверждена")
    return {"sha256": hashlib.sha256(der).hexdigest(), "not_after": ssl.cert_time_to_seconds(cert["notAfter"])}


def check_renewal(before: dict, after: dict) -> None:
    try:
        if before["address"] != after["address"] or set(before["certificates"]) != set(after["certificates"]):
            raise ValueError("Снимки относятся к разным стендам или именам")
        if datetime.fromisoformat(before["time"]) >= datetime.fromisoformat(after["time"]):
            raise ValueError("Базовый снимок должен быть сделан раньше повторного")
        for name, current in after["certificates"].items():
            old = before["certificates"][name]
            if old["sha256"] == current["sha256"] or old["not_after"] >= current["not_after"]:
                raise ValueError(f"Для {name} продление не подтверждено")
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("Некорректный снимок проверки TLS") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True, help="Публичный IP непроизводственного стенда")
    parser.add_argument("--name", action="append", required=True, help="Зарегистрированное DNS-имя стенда")
    parser.add_argument("--previous", type=Path, help="Снимок, сделанный до автоматического продления")
    args = parser.parse_args()
    ip = TLSIdentity(args.ip, True)
    if not ip_address(ip.name).is_global:
        parser.error("Для публичной проверки нужен глобальный адрес")
    names = tuple(dict.fromkeys(TLSIdentity(name, False) for name in args.name))
    if len(names) < 2:
        parser.error("Для аудита нужны два разных DNS-имени")
    context = ssl.create_default_context()
    observed = {}
    for identity in (*names, ip):
        if not identity.is_ip:
            addresses = {ip_address(record[4][0]).compressed for record in socket.getaddrinfo(identity.name, None)}
            if ip.name not in addresses:
                raise RuntimeError(f"DNS {identity.name} не указывает на адрес стенда")
        _http(ip.name, identity)
        public = _tls(ip.name, identity, 443, "/", 200, context)
        _tls(ip.name, identity, 443, "/login", 404, context)
        admin = _tls(ip.name, identity, 8443, "/login", 200, context)
        if public != admin:
            raise RuntimeError(f"Для {identity.name} порты используют разные сертификаты")
        observed[identity.name] = public
    if len({value["sha256"] for value in observed.values()}) != len(observed):
        raise RuntimeError("Разные имена используют одну пару вместо отдельных сертификатов")
    snapshot = {"address": ip.name, "time": datetime.now(timezone.utc).isoformat(), "certificates": observed}
    if args.previous is not None:
        check_renewal(json.loads(args.previous.read_text(encoding="utf-8")), snapshot)
        snapshot["renewal_verified"] = True
    print(json.dumps(snapshot, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
        raise SystemExit(f"Внешняя TLS-проверка не прошла: {exc}")
