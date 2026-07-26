import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "portal" / "app" / "service_catalog.py"


class PortalServiceCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = runpy.run_path(str(CATALOG_PATH))
        cls.catalog = cls.module["SERVICE_CATALOG"]

    def test_catalog_covers_all_systems_and_operator_services(self):
        expected_systems = {
            "tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt",
            "mtg", "amneziawg", "wireguard", "ocserv",
        }
        self.assertEqual(set(self.module["SYSTEM_ORDER"]), expected_systems)
        self.assertTrue(expected_systems.issubset(self.catalog))
        self.assertTrue({"portal", "nginx", "agent"}.issubset(self.catalog))
        for key in expected_systems:
            guide = self.catalog[key]
            self.assertIsInstance(guide.ports, tuple)
            self.assertIsInstance(guide.clients, tuple)
            self.assertIsInstance(guide.limitations, tuple)
            for value in (
                guide.purpose,
                guide.ports,
                guide.clients,
                guide.apply_behavior,
                guide.diagnostics,
            ):
                self.assertTrue(value, key)

    def test_wireguard_clients_and_ports_are_not_interchangeable(self):
        amnezia = self.catalog["amneziawg"]
        wireguard = self.catalog["wireguard"]
        self.assertEqual(amnezia.clients, ("AmneziaWG app",))
        self.assertTrue(any("51820/udp" in port for port in amnezia.ports))
        self.assertFalse(any("Karing" in client for client in amnezia.clients))
        self.assertTrue(any("Karing" in client for client in wireguard.clients))
        self.assertTrue(any("51821/udp" in port for port in wireguard.ports))
        self.assertFalse(any("51820" in port for port in wireguard.ports))

    def test_subscription_guidance_keeps_ip_san_gate_and_file_kinds_canonical(self):
        topic = self.module["GUIDANCE_TOPICS"]["happ-karing"]
        text = " ".join((topic.summary, *topic.details))
        self.assertIn("IP SAN", text)
        self.assertIn("HTTPS URL", text)
        self.assertIn("отдельно", text)
        self.assertEqual(
            self.module["client_file_group"]("karing-wireguard-config"),
            "subscriptions",
        )
        self.assertEqual(
            self.module["client_file_group"]("unknown-future-kind"),
            "other",
        )
        self.assertTrue(self.module["is_qr_file"]("wireguard-qr"))
        self.assertFalse(self.module["is_qr_file"]("wireguard-config"))

    def test_help_contains_no_runtime_secret_values(self):
        combined = "\n".join(
            " ".join((
                guide.purpose,
                guide.credential_scope,
                guide.sni_scope,
                guide.apply_behavior,
                guide.diagnostics,
                *guide.limitations,
            ))
            for guide in self.catalog.values()
        )
        for forbidden in (
            "BEGIN PRIVATE KEY",
            "NeverStoreThis",
            "password_hash",
            "sub_token",
            "agent.secret",
        ):
            self.assertNotIn(forbidden, combined)


if __name__ == "__main__":
    unittest.main()
