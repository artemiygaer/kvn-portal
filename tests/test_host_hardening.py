"""Контракты безопасной установки и host-network без запуска systemd на Windows."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HostHardeningTests(unittest.TestCase):
    def test_portal_resources_fit_small_server_budget(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        portal = compose.split("  portal:\n", 1)[1].split("\n  portal-gateway:\n", 1)[0]
        gateway = compose.split("  portal-gateway:\n", 1)[1].split("\n  nginx:\n", 1)[0]
        for marker in ['cpus: "0.35"', "mem_limit: 192m", "mem_reservation: 96m", "pids_limit: 64"]:
            self.assertIn(marker, portal)
        for marker in ['cpus: "0.15"', "mem_limit: 64m", "mem_reservation: 32m", "pids_limit: 32"]:
            self.assertIn(marker, gateway)

    def test_data_plane_has_no_arbitrary_cpu_quota(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for service, next_service in [
            ("nginx", "telemt"), ("telemt", "mtg"), ("mtg", "hysteria"),
            ("hysteria", "ocserv"), ("ocserv", "xray"),
        ]:
            body = compose.split(f"  {service}:\n", 1)[1].split(f"\n  {next_service}:\n", 1)[0]
            self.assertNotIn("cpus:", body, service)
        xray = compose.split("  xray:\n", 1)[1]
        self.assertNotIn("cpus:", xray, "xray")

    def test_gunicorn_defaults_are_bounded_and_overridable(self):
        dockerfile = (ROOT / "portal/Dockerfile").read_text(encoding="utf-8")
        for marker in [
            "--workers=${KVN_PORTAL_WORKERS:-1}",
            "--threads=${KVN_PORTAL_THREADS:-2}",
            "--timeout=${KVN_PORTAL_TIMEOUT:-1800}",
            "--max-requests=${KVN_PORTAL_MAX_REQUESTS:-600}",
        ]:
            self.assertIn(marker, dockerfile)

    def test_host_agent_has_resource_bounds_and_transient_work_stays_separate(self):
        installer = (ROOT / "portal/install-host-agent.sh").read_text(encoding="utf-8")
        agent = (ROOT / "portal/agent.py").read_text(encoding="utf-8")
        for marker in ["MemoryHigh=192M", "MemoryMax=256M", "CPUQuota=40%", "TasksMax=128"]:
            self.assertIn(marker, installer)
        for marker in ["kvn-project-update-", "kvn-portal-root-shell-", "systemd-run"]:
            self.assertIn(marker, agent)

    def test_dashboard_poll_is_non_overlapping_and_at_least_one_minute(self):
        script = (ROOT / "portal/app/static/dashboard.js").read_text(encoding="utf-8")
        for marker in ["60000 * (2 ** failures)", "if (polling) return", "polling = true", "polling = false", "document.hidden"]:
            self.assertIn(marker, script)

    def test_docker_bootstrap_uses_signed_debian_apt_repository(self):
        source = (ROOT / "setup.sh").read_text(encoding="utf-8")
        for marker in [
            'ID:-}" != "debian"', 'VERSION_ID:-}" != "12"', 'VERSION_ID:-}" != "13"',
            "/etc/apt/keyrings/docker.gpg", "signed-by=/etc/apt/keyrings/docker.gpg",
            "docker-ce-cli", "docker-compose-plugin", "download.docker.com/linux/debian/gpg",
        ]:
            self.assertIn(marker, source)
        self.assertNotIn("get.docker.com | sh", source)
        self.assertNotIn("curl -fsSL https://get.docker.com", source)

    def test_setup_has_no_broad_permission_downgrade(self):
        source = (ROOT / "setup.sh").read_text(encoding="utf-8")
        self.assertNotIn("chmod -R 755", source)
        self.assertNotIn("-exec chmod 644 {}", source)
        self.assertIn("chmod 0600 ./users.json", source)
        self.assertIn("portal-runtime/users.json", source)

    def test_host_sync_requires_forwarding_and_keeps_apply_modes(self):
        for relative, tool in [
            ("amneziawg/sync-host-service.sh", "awg"),
            ("wireguard/sync-host-service.sh", "wg"),
        ]:
            source = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(script=relative):
                self.assertIn("ip -4 route show default", source)
                self.assertIn(f"{tool} syncconf", source)
                self.assertIn("STRUCTURAL_CHANGED=false", source)
                self.assertIn("IPv4 forwarding выключен", source)
                self.assertIn("verify_ipv4_forwarding", source)
                self.assertIn("tools/tune-host-network.sh", source)
                self.assertNotIn("sysctl -w", source)
                self.assertNotIn("/etc/sysctl.d", source)
        installer = (ROOT / "portal/install-host-agent.sh").read_text(encoding="utf-8")
        self.assertIn("ProtectKernelTunables=true", installer)

    def test_ocserv_uses_detected_wan_and_fails_closed_on_nat(self):
        source = (ROOT / "ocserv/entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("ip -4 route show default", source)
        self.assertIn("не удалось определить безопасный внешний интерфейс", source)
        self.assertIn("не удалось добавить NAT rule", source)
        self.assertNotIn("-o eth0", source)
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        ocserv = compose.split("  ocserv:\n", 1)[1].split("\n  xray:\n", 1)[0]
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=16m", ocserv)


if __name__ == "__main__":
    unittest.main()
