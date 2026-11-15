"""Подготовка входа только в синтетической копии релиза v4.2."""

import importlib.util
import json
from pathlib import Path
import sys


def main():
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    assert Path("/etc/hostname").read_text().strip() == "kvn-v5-isolated"
    root = Path("/home/kvnlab/v42")
    assert (root / "VERSION").read_text().strip() == "v4.2.0"
    state = root / "users.json"
    body = json.loads(state.read_bytes())
    assert body["users"] == [] and body["portal"]["domain"] == "1.1.1.1"
    assert body["portal"]["performance"]["profile"] == "light"
    spec = importlib.util.spec_from_file_location("fixture_security", root / "portal/app/security.py")
    security = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(security)
    digest = security.hash_password(sys.stdin.read().strip())
    body["portal"]["password_hash"] = digest
    state.write_text(json.dumps(body), encoding="utf-8")
    runtime = root / "portal-runtime/users.json"
    if runtime.is_file():
        view = json.loads(runtime.read_bytes())
        assert view["portal"]["domain"] == "1.1.1.1"
        view["portal"]["password_hash"] = digest
        runtime.write_text(json.dumps(view), encoding="utf-8")
    proxy = root / "nginx/portal-gateway.conf"
    old = proxy.read_text(encoding="utf-8")
    expected = "if ($host != 1.1.1.1)"
    if expected not in old:
        assert "if ($host != 127.0.0.1)" in old
    else:
        proxy.write_text(old.replace(expected, "if ($host != 127.0.0.1)"), encoding="utf-8")


if __name__ == "__main__":
    main()
