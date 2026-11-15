"""Команды root для применения, настройки и диагностики модулей v5."""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3
import sys

from v5.core.contracts import MODULE_IDS
from v5.core.network.plan import NetworkConflict
from v5.core.packages.manifest import PackageError
from v5.core.tls.transaction import GatewayApplyError
from v5.modules.host_tunnel.platform import capability
from v5.modules.host_tunnel.state import State, TUNNELS
from v5.modules.hysteria.config import Settings as HysteriaSettings
from v5.modules.mtg.settings import Settings as MTGSettings
from v5.modules.telemt.settings import Settings as TelemtSettings
from v5.modules.xray.config import Settings

from .assembly import build_lifecycle
from .controller import LifecycleError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("enable", "disable"):
        command = sub.add_parser(name)
        command.add_argument("module", choices=sorted(MODULE_IDS))
    command = sub.add_parser("configure-xray")
    command.add_argument("settings", type=Path)
    command = sub.add_parser("configure-hysteria")
    command.add_argument("settings", type=Path)
    command = sub.add_parser("configure-mtproto")
    command.add_argument("module", choices=("telemt", "mtg"))
    command.add_argument("settings", type=Path)
    command = sub.add_parser("configure-tunnel")
    command.add_argument("module", choices=sorted(TUNNELS))
    command.add_argument("settings", type=Path)
    command = sub.add_parser("tunnel-status")
    command.add_argument("module", choices=sorted(TUNNELS))
    command = sub.add_parser("init-tunnel")
    command.add_argument("module", choices=sorted(TUNNELS))
    command.add_argument("--modern", action="store_const", const=True, default=None,
                         help="AmneziaWG 3.1 уже выбран по умолчанию; флаг оставлен для совместимости команд")
    command.add_argument("--egress", help="Интерфейс выхода для IPv4; без него доступ только к подсети туннеля")
    command = sub.add_parser("upgrade")
    command.add_argument("module", choices=sorted(MODULE_IDS))
    command.add_argument("ticket")
    sub.add_parser("reconcile")
    sub.add_parser("status")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Операция требует root\n")
    try:
        if args.operation == "tunnel-status":
            print(json.dumps(asdict(capability(TUNNELS[args.module])), ensure_ascii=False))
            return 0
        lifecycle = build_lifecycle()
        if args.operation == "configure-xray":
            lifecycle.adapters["xray"].configure(Settings.load(args.settings))
        elif args.operation == "configure-hysteria":
            lifecycle.adapters["hysteria"].configure(HysteriaSettings.load(args.settings))
        elif args.operation == "configure-mtproto":
            settings_type = TelemtSettings if args.module == "telemt" else MTGSettings
            lifecycle.adapters[args.module].configure(settings_type.load(args.settings))
        elif args.operation == "configure-tunnel":
            lifecycle.adapters[args.module].configure(State.load(TUNNELS[args.module], args.settings))
        elif args.operation == "init-tunnel":
            adapter = lifecycle.adapters[args.module]
            adapter.configure(adapter.runtime.initial_state(modern=args.modern, egress=args.egress), initial=True)
        elif args.operation == "reconcile":
            lifecycle.reconcile()
        elif args.operation == "status":
            print(json.dumps(lifecycle.inventory.installed(), ensure_ascii=False))
        elif args.operation == "upgrade":
            lifecycle.upgrade(args.module, args.ticket)
        else:
            lifecycle.change(args.module, args.operation == "enable")
    except (LifecycleError, GatewayApplyError, PackageError, NetworkConflict) as exc:
        print(f"Операция модуля отклонена: {getattr(exc, 'code', str(exc))}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error, ValueError):
        print("Операция модуля отклонена: состояние недоступно", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
