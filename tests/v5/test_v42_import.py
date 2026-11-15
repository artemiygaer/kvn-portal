"""Архив v4.2 создаётся настоящим старым экспортёром, только с тестовыми ключами."""

import hashlib
import json
import base64
from contextlib import nullcontext
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
import tomllib
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from tests.v5.fixtures.make_v42_fixture import build_fixture
from v5.core.contracts import UserGrant
from v5.core.migration.crypto import ArchiveError, MAX_ENCRYPTED, decrypt_archive, encrypt_archive
from v5.core.migration.export import MigrationExporter
from v5.core.migration.legacy import parse_legacy
from v5.core.migration.material import MigrationMaterial
from v5.core.migration.portable import PortableArchive, from_legacy, normalize_credential
from v5.core.migration.repository import MigrationRepository
from v5.core.migration.service import MigrationService
from v5.core.migration.target import MigrationTarget
from v5.core.packages.manifest import PackageError
from v5.core.packages.registry import PackageRegistry
from v5.core.private_files import write_private
from v5.core.tls.identity import TLSIdentity
from v5.core.users.model import SubscriptionToken, User
from v5.core.users.credentials import StoredCredentials
from v5.core.users.store import UserStore
from v5.modules.host_tunnel.config import Peer, Settings as TunnelSettings, WG
from v5.modules.host_tunnel.credentials import allocate, public_key
from v5.modules.host_tunnel.state import State as TunnelState
from v5.modules.hysteria.config import Settings as HySettings, render_server as render_hysteria
from v5.modules.hysteria.users import set_user as project_hysteria, subscription_uris as hy_uris
from v5.modules.mtg.adapter import mtg_adapter
from v5.modules.mtg.settings import Settings as MtgSettings
from v5.modules.mtproto_common.profiles import CoverTarget, Exposure as MtExposure, Secret
from v5.modules.telemt.adapter import telemt_adapter
from v5.modules.telemt.settings import Account as TelemtAccount, Settings as TelemtSettings, client_profile
from v5.modules.telemt.users import set_user as project_telemt
from v5.modules.xray.config import Settings as XraySettings, render_server as render_xray
from v5.modules.xray.credentials import load_reality, profile_reality_keys
from v5.modules.xray.profiles import Exposure, Kind, Profile, Profiles, Reality
from v5.modules.xray.users import set_user as project_xray, subscription_uris as xray_uris

PHRASE = "only-a-synthetic-passphrase"


class ArchiveCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = build_fixture()

    def test_decrypts_archive_written_by_v42_exporter(self):
        document = json.loads(decrypt_archive(self.archive, PHRASE))
        self.assertEqual((document["format"], document["version"]), ("kvn-vpn-migration", 1))
        self.assertGreater(len(document["users"]), 0)

    def test_rejects_wrong_phrase_and_tampering_without_disclosing_data(self):
        tampered = bytearray(self.archive)
        tampered[-10] ^= 1
        for data, phrase in ((self.archive, "another-fixture-passphrase"), (bytes(tampered), PHRASE),
                             (self.archive[:-12], PHRASE)):
            with self.subTest(size=len(data)), self.assertRaisesRegex(ArchiveError, "^migration_archive_invalid$"):
                decrypt_archive(data, phrase)

    def test_validates_limits_and_phrase_before_launch(self):
        with self.assertRaisesRegex(ArchiveError, "^migration_archive_size$"):
            decrypt_archive(b"x" * (MAX_ENCRYPTED + 1), PHRASE)
        with self.assertRaisesRegex(ArchiveError, "^migration_phrase_invalid$"):
            decrypt_archive(self.archive, PHRASE + "\n")

    def test_v5_archive_encrypts_and_roundtrips(self):
        plain = b'{"format":"kvn-vpn-migration","version":2}'
        encrypted = encrypt_archive(plain, PHRASE)
        self.assertNotIn(plain, encrypted)
        self.assertEqual(decrypt_archive(encrypted, PHRASE), plain)


class LegacySchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plain = decrypt_archive(build_fixture(), PHRASE)

    def test_identity_and_allowed_material_preserved_without_openconnect(self):
        archive = parse_legacy(self.plain)
        (row,) = archive.users
        raw = json.loads(self.plain)["users"][0]
        self.assertEqual(row.user.name, raw["name"])
        self.assertEqual(row.user.id, raw["uuid"].replace("-", ""))
        self.assertEqual(row.token_digest, hashlib.sha256(raw["sub_token"].encode()).digest())
        self.assertTrue(SubscriptionToken(raw["sub_token"]).matches(row.token_digest))
        self.assertEqual(len(SubscriptionToken.create().value), 43)
        with self.assertRaises(ValueError):
            SubscriptionToken("z" * 32)
        self.assertEqual(row.credentials["wireguard"], raw["wireguard"])
        self.assertEqual(row.credentials["hysteria_password"], raw["hysteria_password"])
        self.assertNotIn("ocserv", row.systems)
        self.assertEqual(row.skipped, ("ocserv",))
        self.assertNotIn("ocserv_password", row.credentials)
        self.assertNotIn("ocserv", archive.protocols)
        self.assertNotIn(raw["sub_token"], repr(archive))

    def test_archive_with_only_openconnect_user_keeps_reportable_card(self):
        def only_openconnect(state):
            state["users"][0]["systems"] = ["ocserv"]
        archive = parse_legacy(decrypt_archive(build_fixture(only_openconnect), PHRASE))
        (row,) = archive.users
        self.assertEqual(row.systems, ())
        self.assertEqual(row.skipped, ("ocserv",))
        self.assertEqual(row.credentials.keys(), {"uuid"})
        (portable,) = from_legacy(archive).users
        self.assertEqual(portable.user, row.user)
        self.assertEqual((portable.grants, portable.credentials, portable.skipped), ((), (), ("ocserv",)))

    def test_duplicate_identity_and_unexpected_keys_are_rejected(self):
        for field in ("name", "uuid", "sub_token"):
            data = json.loads(self.plain)
            row = {**data["users"][0], "name": "another", "uuid": "00000000-0000-4000-8000-000000000002",
                   "sub_token": "1" * 32}
            row[field] = data["users"][0][field]
            data["users"].append(row)
            with self.subTest(field=field), self.assertRaisesRegex(ArchiveError, "^migration_identity_conflict$"):
                parse_legacy(json.dumps(data).encode())
        data = json.loads(self.plain)
        data["protocols"]["wireguard"]["post_up"] = "fixture-forbidden"
        with self.assertRaisesRegex(ArchiveError, "^migration_schema_invalid$"):
            parse_legacy(json.dumps(data).encode())

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(ArchiveError, "^migration_schema_invalid$"):
            parse_legacy(b'{"format":"ignored",' + self.plain[1:])


class ImportTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.encrypted = build_fixture()
        cls.plain = decrypt_archive(cls.encrypted, PHRASE)
        cls.archive = from_legacy(parse_legacy(cls.plain))

    def setUp(self):
        folder = self.enterContext(TemporaryDirectory())
        self.store = UserStore(Path(folder) / "users")
        self.now, self.host, self.empty = 1000, "a" * 64, True
        self.owner = "f" * 64
        self.repo = MigrationRepository(self.store, guard=nullcontext, restore_ready=lambda: self.empty,
                                        check_target=lambda *_: None, clock=lambda: self.now,
                                        target_revision=lambda: self.host)

    def test_restore_preserves_credentials_and_token_without_activating(self):
        preview = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        self.assertEqual(self.repo.current().users, ())
        self.assertEqual(preview.skipped_openconnect, ("AuditFixture",))
        ticket = self.repo.commit(preview.ticket, owner=self.owner)
        self.assertEqual(self.repo.current(), self.archive)
        user, _, grants = self.store.get(self.archive.users[0].user.id)
        self.assertTrue(grants and all(row.grant.enabled and not row.applied for row in grants))
        material = MigrationMaterial(self.store)
        self.assertEqual(material.credential(user.id, "xray")["uuid"], json.loads(self.plain)["users"][0]["uuid"])
        self.assertEqual(set(material.server_seed("xray")), {"reality-tcp", "reality-xhttp"})
        token = SubscriptionToken(json.loads(self.plain)["users"][0]["sub_token"])
        self.assertEqual(self.store.subscription_owner(token), user.id)
        self.assertEqual(stat.S_IMODE(self.store.database.stat().st_mode), 0o600)
        self.assertEqual(self.repo.rollback(ticket), 1)
        self.assertIsNone(self.store.subscription_owner(token))
        self.assertEqual(self.repo.current().users, ())
        self.assertEqual(self.repo.current().seeds, ())
        self.assertIsNone(material.credential(user.id, "xray"))
        self.assertIsNone(material.server_seed("xray"))

    def test_v5_portable_archive_roundtrips_without_openconnect_secret(self):
        payload = self.archive.encode()
        self.assertNotIn(b"ocserv_password", payload)
        encrypted = encrypt_archive(payload, PHRASE)
        self.assertEqual(PortableArchive.parse(json.loads(decrypt_archive(encrypted, PHRASE))), self.archive)
        seeds = json.loads(payload)["seeds"]
        self.assertEqual(set(seeds["xray"]), {"reality-tcp", "reality-xhttp"})
        self.assertNotEqual(seeds["xray"]["reality-tcp"]["short_ids"], seeds["xray"]["reality-xhttp"]["short_ids"])

    def test_service_imports_v42_and_roundtrips_encrypted_v5_without_module_calls(self):
        service = MigrationService(self.repo, export_data=self.repo.current)
        with self.assertRaisesRegex(ArchiveError, "migration_archive_invalid"):
            service.preview(self.encrypted, "incorrect-synthetic-phrase", mode="restore", owner=self.owner)
        self.assertFalse(self.repo.current().users)
        preview = service.preview(self.encrypted, PHRASE, mode="restore", owner=self.owner)
        rollback = service.commit(preview.ticket, owner=self.owner)
        outgoing = service.export(PHRASE)
        self.assertEqual(service.rollback(rollback), 1)
        restored = service.preview(outgoing, PHRASE, mode="restore", owner=self.owner)
        service.commit(restored.ticket, owner=self.owner)
        self.assertEqual(self.repo.current(), self.archive)

    def test_merge_adds_users_keeps_destination_keys_and_rejects_collision(self):
        initial = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        self.repo.commit(initial.ticket, owner=self.owner)
        before = self.repo.current()
        with self.assertRaisesRegex(ArchiveError, "migration_identity_conflict"):
            self.repo.preview(self.archive, mode="merge", owner=self.owner)
        document = self.archive.document()
        document["users"] = [{"id": "other", "name": "Other", "enabled": True, "token_digest": None,
                              "grants": {"xray": True}, "credentials": {}, "skipped": []}]
        document["seeds"]["mtg"]["secret"] = "2" * 32
        extra = PortableArchive.parse(document)
        preview = self.repo.preview(extra, mode="merge", owner=self.owner)
        self.assertIn("mtg", preview.ignored_server_keys)
        ticket = self.repo.commit(preview.ticket, owner=self.owner)
        self.assertEqual(self.repo.current().seeds, before.seeds)
        self.assertEqual(len(self.repo.current().users), 2)
        self.assertEqual(self.repo.rollback(ticket), 1)
        self.assertEqual(self.repo.current(), before)

    def test_stale_preview_and_rollback_are_rejected(self):
        preview = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        self.host = "b" * 64
        with self.assertRaisesRegex(ArchiveError, "migration_preview_stale"):
            self.repo.commit(preview.ticket, owner=self.owner)
        self.assertFalse(self.repo.current().users)
        preview = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        self.store.create(User("other", "Other"))
        with self.assertRaisesRegex(ArchiveError, "migration_preview_stale"):
            self.repo.commit(preview.ticket, owner=self.owner)
        before = self.repo.current()
        preview = self.repo.preview(self.archive, mode="merge", owner=self.owner)
        ticket = self.repo.commit(preview.ticket, owner=self.owner)
        self.store.confirm_module("xray", policy=self.store.module_policy("xray"))
        with self.assertRaisesRegex(ArchiveError, "migration_rollback_stale"):
            self.repo.rollback(ticket)
        self.assertEqual(len(self.repo.current().users), len(before.users) + 1)

    def test_expiry_wrong_owner_and_replay_do_not_mutate_vpn_state(self):
        preview = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        with self.assertRaisesRegex(ArchiveError, "migration_ticket_invalid"):
            self.repo.commit(preview.ticket, owner="e" * 64)
        self.now = preview.expires
        with self.assertRaisesRegex(ArchiveError, "migration_ticket_invalid"):
            self.repo.commit(preview.ticket, owner=self.owner)
        self.assertFalse(self.repo.current().users)
        preview = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        self.repo.commit(preview.ticket, owner=self.owner)
        with self.assertRaisesRegex(ArchiveError, "migration_ticket_invalid"):
            self.repo.commit(preview.ticket, owner=self.owner)
        self.assertEqual(self.repo.current(), self.archive)

    def test_restore_refuses_existing_target_without_writes(self):
        self.empty = False
        with self.assertRaisesRegex(ArchiveError, "migration_restore_not_empty"):
            self.repo.preview(self.archive, mode="restore", owner=self.owner)
        self.assertFalse(self.repo.current().users)

    def test_host_check_rejects_incompatible_keys_and_configured_peer_collision(self):
        target = MigrationTarget(self.store.root.parent / "packages", self.store.root.parent / "gateway")
        target.packages.mkdir(mode=0o700)
        repo = MigrationRepository(self.store, guard=target.guard, restore_ready=target.restore_ready,
                                   check_target=target.check_archive, target_revision=target.revision)
        document = self.archive.document()
        key = base64.b64encode(b"v" * 32).decode("ascii")
        document["users"][0]["credentials"]["wireguard"]["public_key"] = public_key(key)
        invalid = PortableArchive.parse(document)
        with self.assertRaisesRegex(ArchiveError, "^migration_wireguard_conflict$"):
            repo.preview(invalid, mode="restore", owner=self.owner)
        self.assertEqual(repo.current().users, ())
        root = target.modules / WG.module
        target.modules.mkdir(mode=0o700)
        root.mkdir(mode=0o700)
        config = root / "settings.json"
        reserved = Peer(public_key(base64.b64encode(b"w" * 32).decode("ascii")), "10.67.67.2")
        native = TunnelState(WG, TunnelSettings(WG.address, key, (reserved,)))
        native.save(config)
        before = target.revision()
        with self.assertRaisesRegex(ArchiveError, "^migration_wireguard_conflict$"):
            repo.preview(self.archive, mode="merge", owner=self.owner)
        self.assertEqual(target.revision(), before)
        self.assertEqual(repo.current().users, ())
        with self.store._connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM migration_previews").fetchone()[0], 0)

    def test_interrupted_commit_rolls_back_keys_users_and_ticket_together(self):
        preview = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        with self.store._connection(write=True) as db:
            db.execute("CREATE TRIGGER migration_fixture_error BEFORE INSERT ON migration_credentials "
                       "WHEN NEW.module='wireguard' BEGIN SELECT RAISE(ABORT, 'fixture'); END")
        with self.assertRaisesRegex(ArchiveError, "migration_identity_conflict"):
            self.repo.commit(preview.ticket, owner=self.owner)
        self.assertFalse(self.repo.current().users)
        with self.store._connection(write=True) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM migration_backup").fetchone()[0], 0)
            db.execute("DROP TRIGGER migration_fixture_error")
        self.repo.commit(preview.ticket, owner=self.owner)
        self.assertEqual(self.repo.current(), self.archive)

    def test_host_guard_allows_import_without_opening_package_registry(self):
        root = self.store.root.parent
        packages, gateway = root / "packages", root / "gateway"
        for path in (packages, gateway):
            path.mkdir(mode=0o700)
        write_private(gateway / "identities.json", b'{"ip":"192.0.2.5"}')
        target = MigrationTarget(packages, gateway)
        repo = MigrationRepository(self.store, guard=target.guard, restore_ready=target.restore_ready,
                                   check_target=target.check_archive, target_revision=target.revision)
        preview = repo.preview(self.archive, mode="restore", owner=self.owner)
        self.assertFalse((packages / "registry.sqlite3").exists())
        self.assertFalse((root / "modules").exists())
        with target.guard(), self.assertRaisesRegex(PackageError, "module_operation_busy"):
            repo.commit(preview.ticket, owner=self.owner)
        snapshot = repo.commit(preview.ticket, owner=self.owner)
        self.assertEqual(repo.current(), self.archive)
        self.assertEqual(repo.rollback(snapshot), 1)
        self.assertEqual({path.name for path in packages.iterdir()}, {"runtime.lock"})

    def test_host_guard_rejects_network_journal_and_detects_changed_config(self):
        root = self.store.root.parent
        packages, gateway = root / "packages", root / "gateway"
        for path in (packages, gateway):
            path.mkdir(mode=0o700)
        package_registry = PackageRegistry(packages, publisher=None)
        target = MigrationTarget(packages, gateway)
        with target.guard():
            before = target.revision()
            self.assertTrue(target.restore_ready())
            with self.assertRaisesRegex(PackageError, "module_operation_busy"), package_registry.runtime_guard():
                pass
        with package_registry._connection(write=True) as db:
            db.execute("INSERT INTO journal(at,action,module,archive) VALUES(?,?,?,?)", (1, "test", "xray", "fixture"))
        with target.guard():
            self.assertNotEqual(before, target.revision())
            before = target.revision()
        module = root / "modules" / "xray"
        module.parent.mkdir(mode=0o700)
        module.mkdir(mode=0o700)
        write_private(module / "settings.json", b'{"fixture":true}')
        with target.guard():
            self.assertFalse(target.restore_ready())
            self.assertNotEqual(before, target.revision())
        write_private(module / "users.pending.json", b"fixture")
        with self.assertRaisesRegex(ArchiveError, "migration_target_busy"), target.guard():
            pass

    def test_xray_projection_retains_distinct_reality_keys_uuid_and_profile_selection(self):
        doc = self.archive.document()
        doc["seeds"]["xray"]["reality-tcp"]["private"] = base64.urlsafe_b64encode(b"q" * 32).decode().rstrip("=")
        doc["seeds"]["xray"]["reality-tcp"]["short_ids"] = ["aabb", ""]
        doc["users"][0]["credentials"]["xray"]["profiles"] = ["reality-tcp", "reality-xhttp"]
        preview = self.repo.preview(PortableArchive.parse(doc), mode="restore", owner=self.owner)
        self.repo.commit(preview.ticket, owner=self.owner)
        user = self.archive.users[0].user
        material = MigrationMaterial(self.store)
        profile_set = Profiles((Profile(Kind.TLS, Exposure.DIRECT, "vpn.example"),
                                Profile(Kind.REALITY_TCP, Exposure.SHARED, "one.example", Reality.EXTERNAL, "one.example"),
                                Profile(Kind.REALITY_XHTTP, Exposure.SHARED, "two.example", Reality.EXTERNAL,
                                        "two.example", "/content")))
        data = material.credential(user.id, "xray")
        state = project_xray(XraySettings(profile_set), user.id, True, imported=data)
        root = self.store.root / "reality.json"
        keys = profile_reality_keys(root, profile_set.values, imported=material.server_seed("xray"), create=True)
        self.assertFalse(root.exists(), "Не создавать общий ключ вместо двух восстановленных")
        tls, tcp, xhttp = render_xray(state, keys, site_names=())["inbounds"]
        self.assertEqual(tls["settings"]["users"], [])
        for item in (tcp, xhttp):
            self.assertEqual(item["settings"]["users"][0]["id"], data["uuid"])
            self.assertEqual(item["streamSettings"]["realitySettings"]["privateKey"],
                             doc["seeds"]["xray"][item["tag"]]["private"])
        self.assertEqual(tcp["streamSettings"]["realitySettings"]["shortIds"], ["aabb", ""])
        uris = xray_uris(state, user.id, "vpn.example", {name: key.public for name, key in keys.items()})
        self.assertEqual(len(uris), 2)
        self.assertEqual([parse_qs(urlsplit(uri).query)["pbk"][0] for uri in uris],
                         [keys[name].public.key for name in (Kind.REALITY_TCP, Kind.REALITY_XHTTP)])
        self.assertEqual(project_xray(state, user.id, False, imported=data).accounts[0].id, data["uuid"])

    def test_hysteria_projection_keeps_legacy_login_password_and_revocation(self):
        preview = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        self.repo.commit(preview.ticket, owner=self.owner)
        user = self.archive.users[0].user
        data = MigrationMaterial(self.store).credential(user.id, "hysteria")
        state = project_hysteria(HySettings(TLSIdentity("vpn.example", False)), user.id, True, imported=data)
        self.assertEqual(render_hysteria(state)["auth"]["userpass"], {data["login"]: data["password"]})
        path = self.store.root / "hy-settings.json"
        state.save(path)
        self.assertEqual(HySettings.load(path), state)
        self.assertEqual(urlsplit(hy_uris(state, user.id, imported=data)[0]).username, data["login"])
        disabled = project_hysteria(state, user.id, False, imported=data)
        self.assertEqual(hy_uris(disabled, user.id, imported=data), ())
        self.assertEqual(project_hysteria(disabled, user.id, True, imported=data), state)

    def test_first_mtg_configuration_retains_shared_secret_without_restoring_old_sni(self):
        preview = self.repo.preview(self.archive, mode="restore", owner=self.owner)
        self.repo.commit(preview.ticket, owner=self.owner)
        material = MigrationMaterial(self.store)
        packages = SimpleNamespace(runtime_guard=nullcontext, require_network_idle=lambda: None,
                                   installed=lambda: ({"module": "mtg", "enabled": False},))
        context = SimpleNamespace(packages=packages, material=material, gateway=SimpleNamespace(site_names=()))
        root = self.store.root.parent / "modules" / "mtg"
        adapter = mtg_adapter(context, root=root)
        settings = MtgSettings(MtExposure("proxy.example"), Secret("2" * 32))
        self.assertFalse(root.exists())
        with patch.object(adapter, "running", return_value=False):
            adapter.configure(settings)
            self.assertEqual(adapter.settings().exposure, settings.exposure)
            self.assertEqual(adapter.settings().secret.value, material.server_seed("mtg")["secret"])
            adapter.configure(settings)
            self.assertEqual(adapter.settings(), settings)

    def test_telemt_projects_imported_key_and_revokes_last_user_without_default_key(self):
        doc = self.archive.document()
        doc["seeds"]["telemt"] = {"Legacy.reader": {"secret": "b" * 32, "enabled": False}}
        preview = self.repo.preview(PortableArchive.parse(doc), mode="restore", owner=self.owner)
        self.repo.commit(preview.ticket, owner=self.owner)
        material = MigrationMaterial(self.store)
        packages = SimpleNamespace(runtime_guard=nullcontext, require_network_idle=lambda: None,
                                   installed=lambda: ({"module": "telemt", "enabled": False},))
        context = SimpleNamespace(packages=packages, material=material, gateway=SimpleNamespace(site_names=()))
        root = self.store.root.parent / "modules" / "telemt"
        adapter = telemt_adapter(context, root=root)
        settings = TelemtSettings(MtExposure("proxy.example"), ())
        with patch.object(adapter, "running", return_value=False):
            adapter.configure(settings)
        saved = adapter.settings()
        self.assertEqual(saved.accounts, (TelemtAccount("Legacy.reader", Secret("b" * 32), False),))
        uid = self.archive.users[0].user.id
        imported = material.credential(uid, "telemt")
        active = project_telemt(saved, uid, True, imported=imported)
        cover = CoverTarget("1.1.1.1", 443)
        self.assertEqual(tomllib.loads(adapter.render(active, cover).decode())["access"]["users"],
                         {uid: imported["secret"]})
        self.assertEqual(client_profile(active, uid, "vpn.example", active=True).secret.value, imported["secret"])
        off = project_telemt(active, uid, False, imported=imported)
        users = tomllib.loads(adapter.render(off, cover).decode())["access"]["users"]
        self.assertEqual(set(users), {"_kvn_no_user"})
        self.assertNotIn(users["_kvn_no_user"], {imported["secret"], "b" * 32, "0" * 32})
        self.assertEqual(stat.S_IMODE((root / "idle-auth.json").stat().st_mode), 0o600)
        self.assertIsNone(client_profile(off, uid, "vpn.example", active=True))
        self.assertEqual(project_telemt(off, uid, True, imported=imported), active)

    def test_native_encrypted_export_roundtrips_credentials_without_runtime(self):
        root = self.store.root.parent
        target = MigrationTarget(root / "packages", root / "gateway")
        target.packages.mkdir(mode=0o700)
        uid = "native"
        self.store.create(User(uid, "native"))
        revision = self.store.get(uid)[1]
        for name in ("xray", "hysteria", "telemt", "wireguard"):
            revision = self.store.set_grant(UserGrant(uid, name, False), revision=revision)
        xray = project_xray(XraySettings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, "fixture.example"),))), uid, True)
        xray = project_xray(xray, uid, False)
        hy = project_hysteria(project_hysteria(HySettings(TLSIdentity("fixture.example", False)), uid, True), uid, False)
        telemt = project_telemt(TelemtSettings(MtExposure("fixture.example"), (
            TelemtAccount("Legacy.reader", Secret("d" * 32), False),)), uid, True)
        telemt = project_telemt(telemt, uid, False)
        native_mtg = MtgSettings(MtExposure("fixture.example"), Secret("e" * 32))
        wg = TunnelState(WG, TunnelSettings(WG.address, base64.b64encode(b"k" * 32).decode("ascii")))
        wg_key = StoredCredentials(self.store, normalize_credential).ensure(uid, WG.module, lambda peers: allocate(wg.settings, peers))
        target.modules.mkdir(mode=0o700)
        for name, settings in (("xray", xray), ("hysteria", hy), ("telemt", telemt), ("mtg", native_mtg), ("wireguard", wg)):
            directory = target.modules / name
            directory.mkdir(mode=0o700)
            settings.save(directory / "settings.json")
        key = load_reality(target.modules / "xray/reality.json", create=True)
        source = MigrationService(self.repo, export_data=MigrationExporter(self.repo, target).collect)
        encrypted = source.export(PHRASE)
        raw = decrypt_archive(encrypted, PHRASE)
        doc = json.loads(raw)
        keys = doc["users"][0]["credentials"]
        self.assertEqual(keys["xray"], {"uuid": xray.accounts[0].id, "profiles": ["tls"]})
        self.assertEqual(keys["hysteria"], {"login": uid, "password": hy.accounts[0].password})
        self.assertEqual(keys["telemt"]["secret"], telemt.accounts[1].secret.value)
        self.assertEqual(keys["wireguard"], wg_key)
        self.assertEqual(doc["seeds"]["wireguard"]["private_key"], wg.settings.private_key)
        self.assertEqual(doc["seeds"]["xray"]["reality-tcp"]["private"], key.private)
        self.assertEqual(doc["seeds"]["mtg"], {"secret": native_mtg.secret.value})
        self.assertFalse(doc["seeds"]["telemt"]["Legacy.reader"]["enabled"])
        self.assertNotIn(b"fixture.example", raw)
        self.assertNotIn(raw, encrypted)
        self.assertFalse((target.packages / "registry.sqlite3").exists())
        destination = root / "destination"
        destination.mkdir(mode=0o700)
        receiving = MigrationTarget(destination / "packages", destination / "gateway")
        receiving.packages.mkdir(mode=0o700)
        restored = MigrationRepository(UserStore(destination / "users"), guard=receiving.guard,
                                       restore_ready=receiving.restore_ready, check_target=receiving.check_archive,
                                       target_revision=receiving.revision)
        service = MigrationService(restored, export_data=restored.current)
        preview = service.preview(encrypted, PHRASE, mode="restore", owner=self.owner)
        service.commit(preview.ticket, owner=self.owner)
        self.assertEqual(restored.current(), PortableArchive.parse(doc))
        self.assertFalse(receiving.modules.exists())
