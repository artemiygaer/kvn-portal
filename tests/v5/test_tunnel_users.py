"""Право, ключи и восстановление туннеля под пользовательским журналом."""

from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from tests.v5.fixtures.make_v42_fixture import build_fixture
from v5.core.contracts import UserGrant
from v5.core.lifecycle.controller import LifecycleError
from v5.core.migration.material import MigrationMaterial
from v5.core.migration.portable import normalize_credential
from v5.core.migration.repository import MigrationRepository
from v5.core.migration.service import MigrationService
from v5.core.users.controller import UserController
from v5.core.users.credentials import StoredCredentials
from v5.core.users.journal import PendingUserApply, UserApplyJournal
from v5.core.users.model import User
from v5.core.users.settings_module import SettingsUserModule
from v5.core.users.store import UserStore
from v5.core.users.transaction import TransactionError, UserTransaction
from v5.modules.amneziawg.profile import Profile
from v5.modules.host_tunnel.config import AWG, WG, Settings
from v5.modules.host_tunnel.state import State
from v5.modules.host_tunnel.user_backend import TunnelUserBackend
from v5.modules.host_tunnel.users import client_file, project_user, restore_seed


KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="


class FixtureAdapter:
    """Учебный kernel: состояние отдельно от файла, остановки видны тесту."""

    def __init__(self, root, state):
        self.root, self.spec, self.module = root, state.spec, state.spec.module
        root.mkdir(mode=0o700)
        self.path = root / "settings.json"
        state.save(self.path)
        self.live = state
        self.starts = self.stops = self.syncs = 0
        self.runtime = SimpleNamespace(sync=self.sync)

    def settings(self):
        return State.load(self.spec, self.path)

    def running(self):
        return self.live is not None

    def sync(self, before, after):
        assert self.live == before and before.peer_only(after)
        self.live = after
        self.syncs += 1

    def verify(self):
        if self.settings() != self.live:
            raise LifecycleError("tunnel_peers_mismatch")

    def start(self):
        self.live = self.settings()
        self.starts += 1

    def stop(self):
        self.live = None
        self.stops += 1


class TunnelUserTests(TestCase):
    def setUp(self):
        folder = self.enterContext(TemporaryDirectory())
        self.root = Path(folder)
        self.users = UserStore(self.root / "users")
        self.material = MigrationMaterial(self.users)
        self.keys = StoredCredentials(self.users, normalize_credential)

    def project(self, state, user_id, enabled):
        return project_user(state, user_id, enabled, material=self.material, credentials=self.keys)

    def fixture(self, state):
        adapter = FixtureAdapter(self.root / state.spec.module, state)
        backend = TunnelUserBackend(adapter, self.project)
        journal = UserApplyJournal(adapter.root / "user.pending")
        return adapter, backend, journal

    def test_native_grant_revoke_and_regrant_keep_key_and_apply_without_restart(self):
        self.users.create(User("alice", "Alice"))
        self.users.create(User("bob", "Bob"))
        state = State(WG, Settings(WG.address, KEY))
        adapter, backend, journal = self.fixture(state)
        packages = SimpleNamespace(runtime_guard=nullcontext, require_network_idle=lambda: None,
                                   installed=lambda: ({"module": WG.module, "enabled": True},))
        module = SettingsUserModule(self.users, packages, backend, journal, lambda user, settings: ())
        self.users.confirm_module(WG.module)
        controller = UserController(self.users, {WG.module: module})
        grant = UserGrant("alice", WG.module, True)
        revision = controller.change(grant, revision=1)
        saved = self.material.credential("alice", WG.module)
        self.assertEqual(saved["address"], "10.67.67.2")
        self.assertTrue(self.users.get("alice")[2][0].applied)
        revision = controller.change(UserGrant("alice", WG.module, False), revision=revision)
        self.assertEqual(adapter.live, state)
        self.assertFalse(client_file(adapter.live, saved, endpoint="portal.example", active=True))
        controller.change(UserGrant("bob", WG.module, True), revision=1)
        self.assertEqual(self.material.credential("bob", WG.module)["address"], "10.67.67.3")
        revision = controller.change(grant, revision=revision)
        self.assertEqual(self.material.credential("alice", WG.module), saved)
        self.assertIn(b"Endpoint = portal.example:51821", client_file(adapter.live, saved, endpoint="portal.example", active=True))
        controller.reconcile("alice", WG.module, revision=revision)
        self.assertEqual((adapter.starts, adapter.stops, adapter.syncs), (0, 0, 4))
        self.assertIsNone(journal.read())

    def test_restore_from_v42_uses_original_keys_before_start(self):
        repo = MigrationRepository(self.users, guard=nullcontext, restore_ready=lambda: True,
                                   check_target=lambda *_: None, target_revision=lambda: "a" * 64)
        migration = MigrationService(repo, export_data=repo.current)
        owner = "b" * 64
        preview = migration.preview(build_fixture(), "only-a-synthetic-passphrase", mode="restore", owner=owner)
        migration.commit(preview.ticket, owner=owner)
        (user,) = repo.current().users
        self.assertTrue(all(not item.applied for item in self.users.get(user.user.id)[2]))
        for spec in (WG, AWG):
            with self.subTest(module=spec.module):
                seed = self.material.server_seed(spec.module)
                initial = State(spec, Settings(spec.address, KEY), Profile.modern(KEY) if spec == AWG else None)
                state = restore_seed(initial, seed)
                adapter, backend, _ = self.fixture(state)
                adapter.live = None
                policy = self.users.module_policy(spec.module)
                self.assertEqual(policy, ((user.user.id, True),))
                with patch("v5.modules.host_tunnel.users.allocate", side_effect=AssertionError("Ключ уже импортирован")):
                    backend.project_before_start(policy)
                restored = adapter.settings()
                material = self.material.credential(user.user.id, spec.module)
                self.assertEqual(restored.settings.private_key, seed["private_key"])
                self.assertEqual(restored.settings.peers[0].public_key, material["public_key"])
                self.assertEqual(restored.settings.peers[0].preshared_key, material["preshared_key"])
                exported = client_file(restored, material, endpoint="portal.example", active=True)
                self.assertIn(material["private_key"].encode(), exported)
                self.assertNotIn(seed["private_key"].encode(), exported)
                self.assertEqual((adapter.starts, adapter.stops, adapter.syncs), (0, 0, 0))

    def test_recover_interrupted_sync_with_old_file_and_new_kernel(self):
        self.users.create(User("alice", "Alice"))
        state = State(WG, Settings(WG.address, KEY))
        adapter, backend, journal = self.fixture(state)
        grant = UserGrant("alice", WG.module, True)
        snapshot = backend.snapshot()
        journal.write(PendingUserApply(grant, 1, snapshot))
        adapter.live = self.project(state, "alice", True)
        self.assertEqual(adapter.settings(), state)
        self.assertTrue(UserTransaction(journal, TunnelUserBackend(adapter, self.project)).recover())
        self.assertEqual((adapter.live, adapter.settings()), (state, state))
        self.assertEqual((adapter.starts, adapter.stops), (1, 1))
        self.assertIsNone(journal.read())

    def test_sync_rolled_back_if_file_save_fails(self):
        self.users.create(User("alice", "Alice"))
        state = State(WG, Settings(WG.address, KEY))
        adapter, backend, journal = self.fixture(state)
        with patch.object(State, "save", side_effect=OSError("учебный отказ")):
            with self.assertRaisesRegex(TransactionError, "user_apply_rolled_back"):
                UserTransaction(journal, backend).apply(UserGrant("alice", WG.module, True), revision=1)
        self.assertEqual((adapter.live, adapter.settings()), (state, state))
        self.assertEqual((adapter.starts, adapter.stops, adapter.syncs), (0, 0, 2))
        self.assertIsNone(journal.read())
