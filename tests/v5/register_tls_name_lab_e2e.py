"""Проверить добавление тестового TLS-имени на выделенной Debian VM."""

from pathlib import Path

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22068, ROOT)
    lab.wait()
    fixture = Path('tests/v5/fixtures/register_tls_test_name.py')
    target = '/var/tmp/kvn-v5-phase2/register_tls_test_name.py'
    lab.upload(fixture, target)
    paths = ('/etc/kvn-v5/gateway/identities.json /root/portal/identity.json '
             '/etc/kvn-v5/web/config.json /etc/kvn-v5/gateway/nginx.conf')
    before = lab.run(f'sha256sum {paths}').stdout
    command = (f'cd /usr/local/lib/kvn-v5; PYTHONPATH=. python3 -u {target} '
               '--hostname kvn-v5-isolated --ip 192.0.2.8 --name fifth.portal.example')
    for option in ('--test-rollback', '--test-rollback-after-gateway'):
        failed = lab.run(command + ' ' + option, check=False, timeout=180)
        assert failed.returncode != 0
        assert lab.run(f'sha256sum {paths}').stdout == before
    lab.run(command,
            timeout=180, capture=False)
    result = lab.run('curl --fail --silent --output /dev/null --write-out "%{http_code}" '
                     '--header "Host: fifth.portal.example" http://127.0.0.1/', timeout=30)
    assert result.stdout == b'200', result.stdout
    lab.run('systemctl is-active --quiet kvn-v5-agent kvn-v5-web kvn-v5-gateway')
    print('На отдельной VM новое имя отвечает на HTTP, портал и агент работают.', flush=True)


if __name__ == '__main__':
    main()
