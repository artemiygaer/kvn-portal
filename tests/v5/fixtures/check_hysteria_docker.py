"""Быстрый реальный QUIC-прогон Hysteria2 в WSL без обращения к systemd."""

import argparse
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from check_hysteria_vm import ADDRESS, SITE, check_client, closed, isolated_network
from check_tls_gateway import make_ca, make_pair
from tests.v5.hysteria_lab_e2e import IMAGE
from v5.core.packages.docker_image import Docker, ENV
from v5.core.packages.manifest import canonical_json, json_object
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.transaction import CertificateStore
from v5.modules.hysteria.clients import client_profile
from v5.modules.hysteria.config import Account, Settings, render_server
from v5.modules.hysteria.idle import idle_secret
from v5.modules.hysteria.runtime import (
    Runtime, _generation, inspect_container, listening, publish_certificate, stop_container,
)
from v5.modules.hysteria.users import set_user

PORT = 24443


def pair(root, identity, serial):
    ca, key = make_ca(root)
    store = root / "store"
    store.mkdir(mode=0o700)
    return CertificateStore(store, ca_file=ca).stage(identity, *make_pair(ca, key, identity, serial))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-user", action="store_true")
    args = parser.parse_args()
    assert os.geteuid() == 0 and "microsoft" in os.uname().release.lower(), "Только локальный WSL"
    assert not Path("/var/lib/kvn-v5/modules/hysteria").exists(), "Обнаружено существующее состояние модуля"
    docker = Docker()
    docker.ready()
    assert inspect_container(docker) is None, "Обнаружен существующий контейнер"
    image = docker.inspect(IMAGE)
    assert image is not None and image.os == "linux" and image.arch == "amd64", "Требуется локальный образ по digest"
    with TemporaryDirectory(dir="/var/tmp", prefix="kvn-v5-hy-wsl-") as directory:
        root = Path(directory)
        binary = root / "hysteria"
        copy = docker.run("create", "--network", "none", "--pull=never", image.id).decode().strip()
        try:
            docker.run("cp", f"{copy}:/usr/local/bin/hysteria", str(binary))
        finally:
            docker.run("container", "rm", copy)
        binary.chmod(0o700)
        tls = TLSIdentity(SITE, False)
        off = replace(Account.create("off"), enabled=False)
        settings = Settings(tls, (off,), bind=ADDRESS, port=PORT, salamander=Account.create("obfs").password)
        if args.legacy_user:
            from tests.v5.fixtures.make_v42_fixture import build_fixture
            from v5.core.migration.crypto import decrypt_archive
            from v5.core.migration.legacy import parse_legacy
            from v5.core.migration.portable import from_legacy

            phrase = "only-a-synthetic-passphrase"
            user, = from_legacy(parse_legacy(decrypt_archive(build_fixture(), phrase))).users
            imported = json_object(dict(user.credentials)["hysteria"])
            settings = set_user(settings, user.user.id, True, imported=imported)
            login = imported["login"]
        else:
            login = "reader"
            settings = set_user(settings, login, True)
        profile = client_profile(settings, login, active=True, endpoint=ADDRESS)
        config = _generation(root, canonical_json(render_server(settings)), image.id)
        publish_certificate(root, pair(root, tls, 901))
        runtime = Runtime(image.id, config, settings.binding)
        with isolated_network():
            closed(ADDRESS, PORT)
            with subprocess.Popen(docker.command(*runtime.arguments()), env=ENV,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as worker:
                try:
                    deadline = time.monotonic() + 30
                    while worker.poll() is None and time.monotonic() < deadline:
                        info = inspect_container(docker)
                        if info and info["running"] and listening(info["pid"]):
                            assert runtime.matches(info), "Не совпало объявление порта или mount"
                            break
                        time.sleep(0.4)
                    else:
                        raise AssertionError("Hysteria2 не подтвердил готовность")
                    subprocess.run(
                        ["/usr/bin/setpriv", "--bounding-set=-all", "--nnp", sys.executable, "-c",
                         "from v5.modules.hysteria.runtime import listening; import sys; "
                         "sys.exit(0 if listening(int(sys.argv[1])) else 1)", str(info["pid"])],
                        check=True, timeout=5,
                    )
                    print("WSL: реальный UDP-listener подтверждён по netns контейнера без capabilities.")
                    args = {"directory": root, "binary": binary}
                    check_client(profile, **args)
                    check_client(profile, use_uri=True, **args)
                    for mode in ("bad-auth", "untrusted", "bad-sni"):
                        check_client(profile, mode=mode, **args)
                    check_client(profile, mode="off-user", denied_account=off, **args)
                    print("WSL: трафик через QUIC по профилю и URI; неверный пароль, CA, SNI и отключённый пользователь отвергнуты.")
                    renewal = root / "renewed"
                    renewal.mkdir(mode=0o700)
                    publish_certificate(root, pair(renewal, tls, 902))
                    check_client(profile, **args)
                    check_client(profile, mode="old-ca", **args)
                    assert inspect_container(docker)["id"] == info["id"], "Контейнер заменён при смене сертификата"
                    print("WSL: новая пара TLS принята без перезапуска; прежняя CA отвергнута.")
                finally:
                    stop_container(docker)
                    if worker.poll() is None:
                        worker.wait(timeout=10)
            closed(ADDRESS, PORT)
            print("WSL: UDP-порт подтверждён закрытым после остановки контейнера.")
            inactive = replace(settings, accounts=tuple(replace(item, enabled=False) for item in settings.accounts))
            idle_config = _generation(root, canonical_json(render_server(inactive, idle_secret=idle_secret(root, create=True))),
                                      image.id)
            idle_runtime = Runtime(image.id, idle_config, settings.binding)
            with subprocess.Popen(docker.command(*idle_runtime.arguments()), env=ENV,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as worker:
                try:
                    deadline = time.monotonic() + 30
                    while worker.poll() is None and time.monotonic() < deadline:
                        info = inspect_container(docker)
                        if info and info["running"] and listening(info["pid"]) and idle_runtime.matches(info):
                            break
                        time.sleep(0.4)
                    else:
                        raise AssertionError("Hysteria2 без пользовательских прав не запустился")
                    check_client(profile, mode="off-user", denied_account=profile.account,
                                 directory=root, binary=binary)
                    print("WSL: последний отозванный пользователь отвергнут реальным сервером Hysteria2.")
                finally:
                    stop_container(docker)
                    if worker.poll() is None:
                        worker.wait(timeout=10)
            closed(ADDRESS, PORT)


if __name__ == "__main__":
    main()
