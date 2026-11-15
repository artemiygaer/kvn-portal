"""Проверки базовых контрактов: данные не запускают модуль."""

import unittest

from v5.core.contracts import ModuleDescriptor, UserGrant


class ModuleContractTests(unittest.TestCase):
    def test_descriptor_rejects_unknown_or_incompatible_versions(self):
        self.assertEqual(ModuleDescriptor("xray", "1.2.3").adapter_api, 1)
        for values in (("ocserv", "1", 1, 1), ("xray", "../x", 1, 1),
                       ("xray", "1", True, 1), ("xray", "1", 1, 2)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                ModuleDescriptor(*values)

    def test_grant_checks_identity_and_boolean(self):
        self.assertTrue(UserGrant("alice", "wireguard", True).enabled)
        for values in (("../alice", "xray", True), ("alice", "ocserv", True),
                       ("alice", "xray", 1)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                UserGrant(*values)
