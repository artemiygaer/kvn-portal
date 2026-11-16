"""Закреплённый источник AmneziaWG без добавления глобального PPA в Debian."""

from pathlib import Path
import os
import re
import subprocess

from .debian_provision import Debian, LOCK_FILE, ProvisionError, WORK_ROOT, apt_commands, apt_stage, debian_sources, provision_lock

# Fingerprint подтверждён публичным Launchpad API владельца ~amnezia/ubuntu/ppa.
PPA_FINGERPRINT = '75C9DD72C799870E310542E24166F2C257290828'
PPA_KEY = b'''-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBGV0UhsBEAC33rMndHSN/k+u7gcZbh9/FjgYfGltQAtVe2QDxzn7UV+k/ChX
OrYRw6Izw/DrhaapkNCThK2jwJE64e0NjboLH7UrrmSJLXMfOlDFbyGJVRA+1sTB
lo7kKHY0xiZ1CHDzjKNV3czbesu80A9nuTZYyWHEn9ax6wsqKG3N8SvzQkUrIOVD
2wZjh0p273CCEGkBnax1ghAV3MF8OrsPU6FRJ+ZakzKbu54g68xoV+2813YECme0
JKsWfUUe/1uEJOXCvuACURSxnYr0sihJd8QI/jHSGlfeq72e5MflFEOrnu5xaDSJ
r2W5lvUetG7EGSxtNKd7Jm/KhUV04g7arA0qydRjRToW3QqyzG7VB2nXKz3AOBYN
earWAuBcTkfPvRVchxbjiYonKZA5tIlVrpawMZsdxKvYwl6LVnpBcccFWPhpudfy
4TpCqCxRoAanOCvSirI3/y7TcZMBw643SaxXi1ifGeg6eyMzrLtP3CeonKBHGzrt
1eeKGtEw/PFN4RmwpBePxi+uj0CoTD6zjCQa3c8EeB4Qz7tt6PnpibxdtZE8sBdd
51wSA/fPGi2tFph8IVAsws7oxcQxZYl8CyncKDLcoR4dxVHYdFEDDf1GjRjoQ3Ai
nD7fxD5qYzExe50DBVpuUbWcAiGICNxfvzQtUSRRtMoSHDcvzsy03KC6VwARAQAB
zR5MYXVuY2hwYWQgUFBBIGZvciBJdXJpaSBFZ29yb3bCwY4EEwEKADgWIQR1yd1y
x5mHDjEFQuJBZvLCVykIKAUCZXRSGwIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIX
gAAKCRBBZvLCVykIKBu5D/9akmHCHlUqm2RTTBeTMbLNGc0l6YugpPaCM6vz0O9k
BFP5PfRaNSRzyF7wHFHNY3JUHcor28my1fD8AE4+C3PwXz8tVYLh57UUsp4wjqHY
+MTl/1ngDViPGD3PRjB8ZlO+19yerfplZv1Jaw7FZZv2BZOAXb+ddqUG4EmlzOnC
EhcSDdFrzEBB3RGthjIb3QkKWKGbELDiMfogmsO9BE139Raiw23blagDrbnWsG4j
ReZeu3atjG6AW8eL7m+i7bKKshD2CYVMznI5cYGLMKo9w7sb33uylPj1Vx9O7joP
2GFf2rTpCY8wgzk7i1RqsipJ80u1/DY91Xdizv3f2BBe6UY7qHKoK00O11J0y8yU
is2Asycy33Wy51pf6rCFUBLQu+c1fEypHF6jqANmQwaH7pPBliy4gGWvrVggzV4m
xv7SnRiMi4PFyVwjKWm8dmuMxi/B9s++VG/ed+5aYgJYL58MohG3MUI/L58eitSC
DDcQ1iAnBmawnGMKPqzMgRFB3OU3wDwfh7LNVvQqWpQ4q7pr4Cq1CvZvGoggXWDo
1/vylPsRmiiuNetfsoVYmrkgtj1om07m5Xp1v4SyXJH11c3dc/xfMmn/4RlMWIpq
86IsOjpr3avsw3FVUNCgD5Wf5+rHG+7gNmM6Cm/F8MDfAnnRmsw4h6hgvcJNQT5D
ig==
=OY2W
-----END PGP PUBLIC KEY BLOCK-----
'''


def sources(system: Debian, stage: Path) -> str:
    """Использовать совместимый закреплённый выпуск PPA и отдельный ключ."""
    if (not isinstance(stage, Path) or stage.parent != WORK_ROOT
            or not re.fullmatch(r'apt-[a-f0-9]{32}', stage.name, re.ASCII)):
        raise ProvisionError('invalid_provision_stage')
    base = debian_sources(system)
    suite = 'focal' if system.version == '12' else 'noble'
    return (base + f'deb [signed-by={stage / "amnezia-ppa.asc"}] '
            f'https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu {suite} main\n')


def preferences() -> str:
    """Не допускать зависимости или обновления иных пакетов из Ubuntu PPA."""
    return ('Package: amneziawg-dkms amneziawg-tools\n'
            'Pin: origin "ppa.launchpadcontent.net"\nPin-Priority: 900\n\n'
            'Package: *\nPin: origin "ppa.launchpadcontent.net"\nPin-Priority: -1\n')


def commands(stage: Path, kernel: str) -> tuple[tuple[str, ...], ...]:
    """Фиксированные этапы: обновление, симуляция, сборочные зависимости, AWG."""
    if not isinstance(kernel, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+~-]{0,95}', kernel, re.ASCII):
        raise ProvisionError('invalid_provision_request')
    update, _ = apt_commands(stage, ('wireguard-tools',))
    options = tuple(f'Dir::Etc::preferences={stage}/preferences' if item == 'Dir::Etc::preferences=-' else item
                    for item in update[:-2])
    deps = ('dkms', 'build-essential', 'kmod', 'iproute2', 'nftables', f'linux-headers-{kernel}')
    awg = ('amneziawg-tools', 'amneziawg-dkms')
    flags = ('--no-remove', '--no-upgrade', '--no-install-recommends')
    return (options + ('update', '--error-on=any'),
            options + ('install', '--simulate', *flags, *deps, *awg),
            options + ('install', '-y', *flags, *deps),
            options + ('install', '-y', *flags, *awg))


def run_transaction(system: Debian, kernel: str, *, run=subprocess.run, lock_path: Path = LOCK_FILE) -> None:
    """Установить AWG из закреплённых источников после успешной симуляции."""
    if os.geteuid() != 0:
        raise ProvisionError('provision_requires_root')
    commands(WORK_ROOT / ('apt-' + '0' * 32), kernel)
    debian_sources(system)
    with provision_lock(lock_path), apt_stage(system) as stage:
        for name, content in (('amnezia-ppa.asc', PPA_KEY), ('preferences', preferences().encode('ascii'))):
            fd = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)
            (stage / name).chmod(0o644)
        (stage / 'sources.list').write_text(sources(system, stage), encoding='ascii')
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
               'DEBIAN_FRONTEND': 'noninteractive', 'APT_CONFIG': str(stage / 'apt.conf')}
        for index, command in enumerate(commands(stage, kernel)):
            try:
                result = run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=300 if index < 2 else None, check=False, env=env)
            except subprocess.TimeoutExpired as exc:
                raise ProvisionError('provision_timeout_check_dpkg') from exc
            except OSError as exc:
                raise ProvisionError('provision_apt_unavailable') from exc
            if result.returncode:
                code = ('provision_index_failed' if index == 0 else 'provision_simulation_failed'
                        if index == 1 else 'provision_install_incomplete')
                raise ProvisionError(code)
