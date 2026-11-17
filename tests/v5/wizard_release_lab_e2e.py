"""Точечная проверка выпущенного мастера на отдельной учебной Debian VM."""

from pathlib import Path
import secrets

from tests.v5.debian_core_e2e import Lab


def main():
    lab = Lab(22122, Path('/var/tmp/kvn-v5-lab'))
    lab.password = secrets.token_urlsafe(24)
    lab.wait()
    lab.run("test ! -e /root/portal && test ! -e /etc/kvn-v5 && install -d -m 0700 /var/tmp/kvn-v5-phase2")
    lab.run("cd /var/tmp/kvn-v5-phase2 && curl --disable --fail --location --proto '=https' "
            "--proto-redir '=https' --max-time 120 -o installer.tar.gz "
            "https://github.com/artemiygaer/kvn-portal/releases/download/v5.0.5/kvn-portal-v5-installer.tar.gz")
    lab.run("cd /var/tmp/kvn-v5-phase2 && sha256sum --check --strict && "
            "tar -xzf installer.tar.gz --no-same-owner --no-same-permissions",
            data=b'14ac867c33239c7be2bfb2843b60359459b09d73bfa44438672ffa33a8f18e5b  installer.tar.gz\n')
    prompts = [('Каталог установки', ''), ('IP сервера', '192.0.2.8'), ('Имена DNS', ''),
               ('Логин администратора', 'operator'), ('Пароль администратора', lab.password),
               ('Повторите пароль', lab.password), ('HTTPS-порт панели', '9443'),
               ('Путь панели', '/gaer/'), ('Начать установку?', 'да')]
    lab.install(prompts, 0)
    lab.run("python3 -c 'import json; p=json.load(open(\"/etc/kvn-v5/access.json\")); "
            "assert p == {\"port\":9443,\"prefix\":\"/gaer\"}'")
    lab.run('systemctl is-active --quiet kvn-v5-web kvn-v5-agent kvn-v5-gateway')
    lab.run('test ! -e /usr/bin/docker && test ! -d /var/lib/kvn-v5/modules/xray')
    lab.probe_tunnel()
    print('Выпущенный мастер установил пустую панель с выбранными параметрами.', flush=True)


if __name__ == '__main__':
    main()
