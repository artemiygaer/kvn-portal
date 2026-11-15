"""Добавить тестовое имя только на выделенном стенде с откатом при ошибке."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
from tempfile import NamedTemporaryFile

from v5.core.maintenance.access import _replace, wait_login
from v5.core.tls.controller import GatewayController
from v5.core.tls.gateway import admin_hosts
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.probe import check_nginx, reload_nginx, verify_bootstrap, verify_gateway_revision
from v5.core.tls.queue import GATEWAY_ROOT, TLSQueue, _write_json, registry
from v5.core.tls.transaction import CertificateStore, publish_gateway, read_gateway_config


def restore(path, raw):
    with NamedTemporaryFile(dir=path.parent, prefix='.test-restore-', delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--ip', required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--allow-external-test', action='store_true')
    parser.add_argument('--test-rollback', action='store_true')
    parser.add_argument('--test-rollback-after-gateway', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or socket.gethostname() != args.hostname:
        raise RuntimeError('Не совпадают root-доступ или имя выделенного стенда')
    instance = Path('/var/lib/cloud/data/instance-id')
    isolated = instance.is_file() and instance.read_text().strip() == 'kvn-v5-isolated-001'
    if not isolated and not args.allow_external_test:
        raise RuntimeError('Внешний тестовый стенд требует явного флага')
    if ((args.test_rollback or args.test_rollback_after_gateway)
            and not isolated):
        raise RuntimeError('Проверка отказа допустима только на учебной VM')
    name = TLSIdentity(args.name, False)
    ip = TLSIdentity(args.ip, True)
    gateway, identity_file = GATEWAY_ROOT, Path('/root/portal/identity.json')
    registry_file, web_file = gateway / 'identities.json', Path('/etc/kvn-v5/web/config.json')
    config = gateway / 'nginx.conf'
    with TLSQueue().exclusive():
        identities, ipv6 = registry()
        if ip not in identities or name in identities:
            raise RuntimeError('IP не совпадает или тестовое имя уже зарегистрировано')
        registry_raw, identity_raw = registry_file.read_bytes(), identity_file.read_bytes()
        original_registry, original_identity = json.loads(registry_raw), json.loads(identity_raw)
        original_web = web_file.read_bytes()
        original_gateway = read_gateway_config(config)
        web = json.loads(original_web)
        if (original_registry['ip'] != original_identity['ip']
                or original_registry['names'] != original_identity['names']):
            raise RuntimeError('Исходные реестры имён не согласованы')
        updated = (*identities, name)
        web['allowed_hosts'] = admin_hosts(updated)
        names = original_registry['names'] + [name.name]
        group = web_file.stat().st_gid

        def bootstrap():
            verify_bootstrap(gateway / 'bootstrap.crt')

        try:
            _write_json(registry_file, {**original_registry, 'names': names})
            _write_json(identity_file, {**original_identity, 'names': names})
            _replace(web_file, json.dumps(web, ensure_ascii=True).encode('ascii'), group)
            if args.test_rollback:
                raise RuntimeError('Проверочный отказ для проверки отката')
            controller = GatewayController(config, CertificateStore(gateway / 'certs'), updated, ipv6=ipv6)
            controller.replace_routes(controller.network_routes(), check=check_nginx, reload=reload_nginx,
                                      verify_live=bootstrap, verify_restored=bootstrap,
                                      verify_loaded=lambda body: verify_gateway_revision(body, gateway / 'bootstrap.crt'),
                                      reconcile=True)
            if args.test_rollback_after_gateway:
                raise RuntimeError('Проверочный отказ после применения шлюза')
            subprocess.run(['systemctl', 'restart', 'kvn-v5-web.service'], check=True, timeout=60)
            wait_login(Path('/etc/kvn-v5'), timeout=60)
        except BaseException:
            restore(registry_file, registry_raw)
            restore(identity_file, identity_raw)
            _replace(web_file, original_web, group)
            current = read_gateway_config(config)
            if current != original_gateway:
                publish_gateway(config, original_gateway, check=check_nginx, reload=reload_nginx,
                                verify_live=bootstrap, verify_restored=bootstrap, expected=current)
            subprocess.run(['systemctl', 'restart', 'kvn-v5-web.service'], check=True, timeout=60)
            wait_login(Path('/etc/kvn-v5'), timeout=60)
            raise
    print('Тестовое имя зарегистрировано; прежние сертификаты и маршруты сохранены.')


if __name__ == '__main__':
    main()
