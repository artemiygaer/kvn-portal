"""Проверка сравнения внешних снимков, без обращения к рабочим серверам."""

from copy import deepcopy
import unittest

from tests.v5.public_tls_probe import check_renewal


class ExternalProbeTests(unittest.TestCase):
    def test_requires_later_snapshot_and_newer_pair_for_every_identity(self):
        before = {"address": "192.0.2.8", "time": "2026-11-01T12:00:00+00:00",
                  "certificates": {name: {"sha256": char * 64, "not_after": 100}
                                   for name, char in (("192.0.2.8", "1"), ("one.example", "2"), ("two.example", "3"))}}
        after = deepcopy(before)
        after["time"] = "2026-11-07T12:00:00+00:00"
        for pair in after["certificates"].values():
            pair["sha256"] = pair["sha256"].replace("1", "4").replace("2", "5").replace("3", "6")
            pair["not_after"] = 200
        check_renewal(before, after)
        with self.assertRaises(ValueError):
            check_renewal(after, before)
        with self.assertRaises(ValueError):
            check_renewal(before, {**after, "address": "192.0.2.9"})
        after["certificates"]["one.example"] = before["certificates"]["one.example"]
        with self.assertRaises(ValueError):
            check_renewal(before, after)
