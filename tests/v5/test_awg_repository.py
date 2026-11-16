"""Доверие к источнику AWG не зависит от данных браузера и глобальных APT-настроек."""

from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from types import SimpleNamespace

from v5.core.packages.awg_repository import PPA_FINGERPRINT, PPA_KEY, commands, preferences, run_transaction, sources
from v5.core.packages.debian_provision import Debian, ProvisionError


class AwgRepositoryTests(TestCase):
    def test_public_key_matches_official_launchpad_fingerprint(self):
        with TemporaryDirectory() as directory:
            result = subprocess.run(['/usr/bin/gpg', '--homedir', directory, '--batch', '--no-options',
                                     '--with-colons', '--show-keys'], input=PPA_KEY, capture_output=True, check=True)
        lines = result.stdout.decode('ascii').splitlines()
        self.assertEqual(sum(row.startswith('pub:') for row in lines), 1)
        self.assertEqual([row.split(':')[9] for row in lines if row.startswith('fpr:')], [PPA_FINGERPRINT])

    def test_only_isolated_pinned_ppa_and_two_packages(self):
        stage = Path('/var/tmp') / ('apt-' + 'a' * 32)
        for system, suite in ((Debian('12', 'bookworm'), 'focal'), (Debian('13', 'trixie'), 'noble')):
            result = sources(system, stage)
            self.assertEqual(result.count(f'https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu {suite} main'), 1)
            self.assertIn(f'signed-by={stage}/amnezia-ppa.asc', result)
            self.assertIn(system.codename + '-security', result)
        for bad in (Path('/tmp/apt-' + 'a' * 32), Path('/var/tmp/apt-injection')):
            with self.assertRaisesRegex(ProvisionError, 'invalid_provision_stage'):
                sources(Debian('13', 'trixie'), bad)
        policy = preferences()
        self.assertIn('Package: amneziawg-dkms amneziawg-tools', policy)
        self.assertIn('Package: *\nPin: origin "ppa.launchpadcontent.net"\nPin-Priority: -1', policy)

    def test_install_plan_is_fixed_and_simulated_before_changes(self):
        stage = Path('/var/tmp') / ('apt-' + 'a' * 32)
        update, simulate, prerequisites, install = commands(stage, '6.12.0-1-amd64')
        self.assertIn('--error-on=any', update)
        self.assertIn('--simulate', simulate)
        self.assertIn('linux-headers-6.12.0-1-amd64', prerequisites)
        self.assertEqual(install[-2:], ('amneziawg-tools', 'amneziawg-dkms'))
        for command in (simulate, prerequisites, install):
            self.assertIn('--no-remove', command)
            self.assertIn('--no-upgrade', command)
            self.assertIn(f'Dir::Etc::preferences={stage}/preferences', command)
        for bad in ('x;id', '../../tmp', '', None, 'a' * 97):
            with self.subTest(kernel=bad), self.assertRaisesRegex(ProvisionError, 'invalid_provision_request'):
                commands(stage, bad)

    def test_failed_simulation_never_installs_packages(self):
        with TemporaryDirectory() as directory:
            root, calls = Path(directory), []
            def run(argv, **kwargs):
                calls.append(argv)
                return SimpleNamespace(returncode=1 if '--simulate' in argv else 0)
            with patch('v5.core.packages.awg_repository.WORK_ROOT', root), \
                 patch('v5.core.packages.debian_provision.WORK_ROOT', root), patch('os.geteuid', return_value=0):
                with self.assertRaisesRegex(ProvisionError, 'provision_simulation_failed'):
                    run_transaction(Debian('13', 'trixie'), '6.12.0-1-amd64', run=run, lock_path=root / 'lock')
            self.assertEqual(len(calls), 2)
            self.assertIn('--simulate', calls[-1])
            self.assertFalse(any(item.name.startswith('apt-') for item in root.iterdir()))
