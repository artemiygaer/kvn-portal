"""Контракт безопасного плана подготовки системных зависимостей."""

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
import subprocess

from v5.core.packages.debian_provision import (Debian, ProvisionError, apt_commands, apt_stage, debian_sources,
                                              package_plan, parse_os_release, provision_lock, run_apt_transaction)


class DebianProvisionTests(TestCase):
    def test_supported_sources_are_fixed_and_signed(self):
        for version, codename in (('12', 'bookworm'), ('13', 'trixie')):
            with self.subTest(version=version):
                system = parse_os_release(f'ID=debian\nVERSION_ID="{version}"\nVERSION_CODENAME={codename}\n')
                self.assertEqual(system, Debian(version, codename))
                sources = debian_sources(system)
                self.assertEqual(sources.count('signed-by=/usr/share/keyrings/debian-archive-keyring.gpg'), 3)
                self.assertIn(f'{codename}-security main', sources)
                self.assertNotIn('ubuntu', sources)

    def test_rejects_unknown_or_injected_operating_system(self):
        for raw in ('ID=ubuntu\nVERSION_ID="13"\nVERSION_CODENAME=trixie',
                    'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=bookworm',
                    'ID=debian\nID=ubuntu\nVERSION_ID=13\nVERSION_CODENAME=trixie',
                    'ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie;id', '\x00'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ProvisionError, 'unsupported_debian'):
                parse_os_release(raw)
        with self.assertRaisesRegex(ProvisionError, 'unsupported_debian'):
            debian_sources(Debian('13', 'trixie;id'))

    def test_fixed_modules_do_not_replace_existing_tools(self):
        for module in ('xray', 'hysteria', 'telemt', 'mtg'):
            self.assertEqual(package_plan(module, docker_present=False, wg_present=False, nft_present=False), ('docker.io',))
            self.assertEqual(package_plan(module, docker_present=True, wg_present=False, nft_present=False), ())
            flags = {'docker_present': False, 'wg_present': False, 'nft_present': False}
            self.assertEqual(package_plan(module, system=Debian('13', 'trixie'), **flags), ('docker.io', 'docker-cli'))
            self.assertEqual(package_plan(module, system=Debian('12', 'bookworm'), **flags), ('docker.io',))
            self.assertEqual(package_plan(module, system=Debian('13', 'trixie'), debian_docker_daemon=True, **flags),
                             ('docker-cli',))
            with self.assertRaisesRegex(ProvisionError, 'provision_existing_tools'):
                package_plan(module, system=Debian('12', 'bookworm'), debian_docker_daemon=True, **flags)
        self.assertEqual(package_plan('wireguard', docker_present=False, wg_present=True, nft_present=False), ('nftables',))
        self.assertEqual(package_plan('wireguard', docker_present=False, wg_present=True, nft_present=True), ())
        for module in ('docker.io', '../wireguard', 'wireguard;id', None):
            with self.subTest(module=module), self.assertRaisesRegex(ProvisionError, 'invalid_provision_request'):
                package_plan(module, docker_present=False, wg_present=False, nft_present=False)
        with self.assertRaisesRegex(ProvisionError, 'amneziawg_provision_unavailable'):
            package_plan('amneziawg', docker_present=False, wg_present=False, nft_present=False)
        with self.assertRaisesRegex(ProvisionError, 'invalid_provision_request'):
            package_plan('wireguard', docker_present=1, wg_present=False, nft_present=False)

    def test_apt_commands_are_isolated_and_reject_external_parameters(self):
        root = Path('/var/tmp')
        stage = root / ('apt-' + 'a' * 32)
        update, install = apt_commands(stage, ('wireguard-tools', 'nftables'))
        self.assertEqual(update[0], '/usr/bin/apt-get')
        self.assertEqual(install[-2:], ('wireguard-tools', 'nftables'))
        for flag in ('--no-remove', '--no-upgrade', '--no-install-recommends'):
            self.assertIn(flag, install)
        self.assertIn(f'Dir::Etc::sourceparts={stage}/empty', update)
        self.assertIn(f'Dir::Etc::preferencesparts={stage}/empty', update)
        self.assertIn('APT::Get::AllowUnauthenticated=false', update)
        self.assertEqual(apt_commands(stage, ('docker.io', 'docker-cli'))[1][-2:], ('docker.io', 'docker-cli'))
        for packages in (('wireguard-tools;id',), ('docker.io', 'nftables'), (), ('nftables', 'nftables'), ([],)):
            with self.subTest(packages=packages), self.assertRaisesRegex(ProvisionError, 'invalid_provision_request'):
                apt_commands(stage, packages)
        for path in (Path('/tmp/apt-' + 'a' * 32), root / '../escape', root / ('apt-' + 'z' * 32)):
            with self.subTest(path=path), self.assertRaisesRegex(ProvisionError, 'invalid_provision_stage'):
                apt_commands(path, ('docker.io',))

    def test_stage_is_owned_isolated_and_cleaned_on_error(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'unrelated'
            marker.write_text('сохранить')
            with patch('v5.core.packages.debian_provision.WORK_ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'проверка'):
                    with apt_stage(Debian('13', 'trixie')) as stage:
                        self.assertEqual(stage.parent, root)
                        self.assertEqual(stage.stat().st_mode & 0o777, 0o755)
                        self.assertIn('trixie-security', (stage / 'sources.list').read_text())
                        self.assertIn(f'Dir::Etc::parts "{stage}/empty";', (stage / 'apt.conf').read_text())
                        self.assertTrue((stage / 'lists' / 'partial').is_dir())
                        self.assertTrue((stage / 'archives' / 'partial').is_dir())
                        self.assertTrue(apt_commands(stage, ('docker.io',)))
                        raise RuntimeError('проверка')
                self.assertFalse(stage.exists())
            self.assertEqual(marker.read_text(), 'сохранить')

    def test_transaction_is_serialized_bounded_and_never_executes_user_input(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def run(argv, **kwargs):
                calls.append((argv, kwargs))
                return SimpleNamespace(returncode=0)

            with patch('v5.core.packages.debian_provision.WORK_ROOT', root), patch('os.geteuid', return_value=0):
                lock = root / 'lock'
                with provision_lock(lock):
                    with self.assertRaisesRegex(ProvisionError, 'provision_busy'):
                        run_apt_transaction(Debian('13', 'trixie'), ('docker.io',), run=run, lock_path=lock)
                self.assertEqual(calls, [])
                run_apt_transaction(Debian('13', 'trixie'), ('docker.io',), run=run, lock_path=lock)
                self.assertEqual(len(calls), 2)
                self.assertEqual(calls[0][0][0], '/usr/bin/apt-get')
                self.assertEqual(calls[1][0][-1], 'docker.io')
                self.assertEqual(calls[0][1]['timeout'], 300)
                self.assertIsNone(calls[1][1]['timeout'])
                self.assertEqual(calls[1][1]['env']['DEBIAN_FRONTEND'], 'noninteractive')
                self.assertFalse(any(path.name.startswith('apt-') for path in root.iterdir()))
                with self.assertRaisesRegex(ProvisionError, 'invalid_provision_request'):
                    run_apt_transaction(Debian('13', 'trixie'), ('docker.io;id',), run=run, lock_path=lock)
                self.assertEqual(len(calls), 2)

    def test_transaction_reports_partial_failure_without_retrying_or_removing_packages(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def fail_install(argv, **kwargs):
                calls.append(argv)
                return SimpleNamespace(returncode=0 if len(calls) == 1 else 100)

            with patch('v5.core.packages.debian_provision.WORK_ROOT', root), patch('os.geteuid', return_value=0):
                with self.assertRaisesRegex(ProvisionError, 'provision_install_incomplete'):
                    run_apt_transaction(Debian('12', 'bookworm'), ('wireguard-tools',),
                                        run=fail_install, lock_path=root / 'lock')
                self.assertEqual(len(calls), 2)
                self.assertIn('--no-remove', calls[1])
                self.assertFalse(any(path.name.startswith('apt-') for path in root.iterdir()))

                def timeout(argv, **kwargs):
                    raise subprocess.TimeoutExpired(argv, 300)

                with self.assertRaisesRegex(ProvisionError, 'provision_timeout_check_dpkg'):
                    run_apt_transaction(Debian('12', 'bookworm'), ('wireguard-tools',),
                                        run=timeout, lock_path=root / 'lock')
