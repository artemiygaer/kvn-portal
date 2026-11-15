"""Локальный WSL-прогон двух закреплённых контейнеров и клиента FakeTLS."""

import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import tomllib
from types import SimpleNamespace
from unittest.mock import patch

from check_mtproto_client import cover_https, fake_tls
from check_network_nft import ADDRESSES, HOST, NS, add_client, remove_client, run
from tests.v5.test_packages import new_key
from v5.core.migration.crypto import decrypt_archive
from v5.core.migration.legacy import parse_legacy
from v5.core.migration.portable import from_legacy
from v5.core.packages.docker_image import Docker, ENV
from v5.core.packages.registry import PackageRegistry
from v5.modules.mtg import settings as mtg
from v5.modules.mtproto_common.profiles import PORTS, CoverTarget, Exposure, Secret
from v5.modules.mtproto_common.runtime import MODULES, inspect_container, listening, prepare, stop_container
from v5.modules.telemt import settings as telemt
from v5.modules.telemt.adapter import telemt_adapter
from v5.modules.telemt.users import set_user
from v5.packaging.build_module import build

VERSIONS = {"telemt": ("3.5.17", "b2054b7b179b23e8ec3f90ad2bf69781879519860383b938260ee8d47291f014"),
            "mtg": ("2.3.0", "15028cdbe0b8561d319ebf63b5827f85c8dd2e48d3eba7e7e7df161db69d99e9")}
ADDRESS = ADDRESSES[0]


def closed(port):
    code = ("import errno,socket,sys; s=socket.socket(); s.settimeout(3); "
            "r=s.connect_ex((sys.argv[1],int(sys.argv[2]))); s.close(); "
            "sys.exit(0 if r==errno.ECONNREFUSED else 1)")
    run("/usr/sbin/ip", "netns", "exec", NS, sys.executable, "-c", code, ADDRESS, str(port))


@contextmanager
def running(runtime, docker):
    assert inspect_container(docker, runtime.module) is None
    with subprocess.Popen(docker.command(*runtime.arguments()), env=ENV, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL) as child:
        try:
            deadline = time.monotonic() + 30
            while child.poll() is None and time.monotonic() < deadline:
                entry = inspect_container(docker, runtime.module)
                if entry and entry["running"] and listening(entry["pid"], runtime.address, PORTS[runtime.module]):
                    assert runtime.matches(entry)
                    yield entry["id"]
                    return
                time.sleep(0.4)
            raise AssertionError(f"{runtime.module}: не подтверждён TCP listener, exit={child.poll()}")
        finally:
            stop_container(docker, runtime.module)
            if child.poll() is None:
                child.wait(timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtg-image", required=True, type=Path)
    parser.add_argument("--module", choices=VERSIONS)
    parser.add_argument("--mtg-cover", default="www.microsoft.com")
    parser.add_argument("--with-v42", action="store_true", help="Секрет Telemt из синтетического архива v4.2")
    args = parser.parse_args()
    if args.with_v42 and args.module != "telemt":
        parser.error("--with-v42 требует --module telemt")
    assert os.geteuid() == 0 and "microsoft" in os.uname().release.lower()
    assert all(not (MODULES / module).exists() for module in VERSIONS)
    assert run("/usr/sbin/ip", "link", "show", HOST, check=False).returncode
    assert NS not in run("/usr/sbin/ip", "netns", "list").stdout.decode().split()
    docker = Docker()
    docker.ready()
    assert all(inspect_container(docker, module) is None for module in VERSIONS)
    with TemporaryDirectory(dir="/var/tmp", prefix="kvn-v5-mtproto-wsl-") as folder:
        root = Path(folder)
        key = root / "lab.key"
        packages = PackageRegistry(root / "registry", new_key(key))
        context = SimpleNamespace(packages=packages, gateway=SimpleNamespace(identities=()))
        configs = {
            "telemt": telemt.Settings(Exposure("www.cloudflare.com", shared=False, direct_ip=ADDRESS),
                                      (telemt.Account.create("reader"),)),
            "mtg": mtg.Settings(Exposure(args.mtg_cover, shared=False, direct_ip=ADDRESS), Secret.create()),
        }
        user_name, imported = "reader", None
        if args.with_v42:
            from tests.v5.fixtures.make_v42_fixture import build_fixture
            archive = from_legacy(parse_legacy(decrypt_archive(build_fixture(), "only-a-synthetic-passphrase")))
            user = archive.users[0].document()
            user_name, imported = user["id"], user["credentials"]["telemt"]
            configs["telemt"] = set_user(replace(configs["telemt"], accounts=()), user_name, True, imported=imported)
        now = datetime.now(timezone.utc)
        for module, (version, digest) in VERSIONS.items():
            archive = root / f"kvn-module-{module}-{version}.tar.gz"
            build(archive, key, module_id=module, version=version, image_digest=digest,
                  image=args.mtg_image if module == "mtg" else None,
                  issued_at=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  expires_at=(now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            with archive.open("rb") as stream:
                packages.install(packages.prepare(stream).ticket)
        assert all(not row["enabled"] for row in packages.installed())
        print("WSL: оба подписанных пакета установлены выключенными, контейнеров нет.")
        try:
            add_client()
            runtimes = {}
            for module, render in (("telemt", telemt.render_server), ("mtg", mtg.render_server)):
                state = root / module
                state.mkdir(mode=0o700)
                runtimes[module] = prepare(module, state, configs[module], render, context, docker)
            profiles = (
                telemt.client_profile(configs["telemt"], user_name, ADDRESS, active=True, direct=True),
                mtg.client_profile(configs["mtg"], ADDRESS, active=True, allowed=True, direct=True),
            )
            if args.module:
                profiles = tuple(item for item in profiles if item.module == args.module)
            with ExitStack() as lifecycle:
                owners = {}
                for profile in profiles:
                    owner = ExitStack()
                    lifecycle.enter_context(owner)
                    owner.enter_context(running(runtimes[profile.module], docker))
                    owners[profile.module] = owner
                for profile in profiles:
                    fake_tls(profile)
                    fake_tls(replace(profile, secret=Secret.create()), expected=False)
                    print(f"WSL {profile.module}: FakeTLS и Telegram resPQ по URI; чужой секрет отклонён.")
                    cover_https(profile)
                    print(f"WSL {profile.module}: TCP listener и внешний TLS/HTTP подтверждены.")
                if len(profiles) == 2:
                    owners["mtg"].close()
                    assert inspect_container(docker, "mtg") is None
                    closed(PORTS["mtg"])
                    assert inspect_container(docker, "telemt")["running"]
                    fake_tls(profiles[0])
                    print("WSL: после выключения MTG его порт закрыт; Telemt продолжает передавать MTProto.")
            assert all(inspect_container(docker, module) is None for module in VERSIONS)
            if args.with_v42:
                previous = profiles[0]
                state = root / "telemt"
                adapter = telemt_adapter(context, root=state, docker=docker)
                revoked = set_user(configs["telemt"], user_name, False, imported=imported)
                native = tomllib.loads((runtimes["telemt"].folder / "config.toml").read_text(encoding="ascii"))["censorship"]
                cover = CoverTarget(native["mask_host"], native["mask_port"])
                # Оба состояния проверяются с тем же уже проверенным cover, без нового DNS/TLS probe.
                with patch("v5.modules.mtproto_common.runtime.cover_target", return_value=cover):
                    runtime = prepare("telemt", state, revoked, adapter.render, context, docker)
                with running(runtime, docker):
                    fake_tls(previous, expected=False)
                    cover_https(previous)
                restored = set_user(revoked, user_name, True, imported=imported)
                assert restored == configs["telemt"]
                with patch("v5.modules.mtproto_common.runtime.cover_target", return_value=cover):
                    runtime = prepare("telemt", state, restored, adapter.render, context, docker)
                with running(runtime, docker):
                    fake_tls(previous)
                print("WSL Telemt: секрет v4.2 принят, последний отзыв отклоняет старый ключ, повторная выдача возвращает его.")
            for profile in profiles:
                closed(PORTS[profile.module])
            print("WSL: оба учебных контейнера остановлены.")
        finally:
            remove_client()


if __name__ == "__main__":
    main()
