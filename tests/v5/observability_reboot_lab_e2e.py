"""Дважды перезагрузить только проверенную учебную VM и проверить автозапуск истории."""

import socket
import subprocess
import time

from tests.v5.debian_core_e2e import Lab
from tests.v5.observability_history_lab_e2e import history, lifecycle
from tests.v5.prepare_tunnel_lab import ROOT


def reboot(lab):
    before = lab.run("cat /proc/sys/kernel/random/boot_id").stdout
    lab.run("systemctl --no-wall reboot", check=False, timeout=30)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 22062), timeout=2):
                pass
        except OSError:
            break
        time.sleep(2)
    else:
        raise RuntimeError("Учебная VM не завершилась перед reboot")
    subprocess.run(["qemu-system-x86_64", "-machine", "accel=tcg", "-cpu", "max", "-m", "1024", "-smp", "1",
                    "-drive", "file=phase12-debian13.qcow2,format=qcow2,if=virtio", "-cdrom", "seed.iso",
                    "-nic", "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:22062-:22", "-display", "none",
                    "-monitor", "none", "-serial", "file:phase13-reboot.log", "-no-reboot",
                    "-pidfile", "phase13-reboot.pid", "-daemonize"], cwd=ROOT, check=True, timeout=30)
    lab.wait()
    assert lab.run("cat /proc/sys/kernel/random/boot_id").stdout != before


def main():
    lab = Lab(22062, ROOT)
    lab.wait()
    assert lifecycle(lab, "history_configure(True)") == {"enabled": True, "active": True}
    reboot(lab)
    assert lifecycle(lab, "history_status()") == {"enabled": True, "active": True}
    print("Reboot: включённый сборщик истории запущен автоматически.", flush=True)
    assert lifecycle(lab, "history_configure(False)") == {"enabled": False, "active": False}
    reboot(lab)
    assert lifecycle(lab, "history_status()") == {"enabled": False, "active": False}
    assert history(lab)["captured_count"] == 0
    print("Reboot: выключенный сборщик не запустился, история отсутствует.", flush=True)


if __name__ == "__main__":
    main()
