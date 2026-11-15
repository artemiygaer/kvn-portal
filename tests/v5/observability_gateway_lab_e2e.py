"""Проверка nginx-конфигурации нового маршрута без применения к VM."""

import shlex

from tests.v5.audit_lab_e2e import INSTALLED, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22062, ROOT)
    lab.wait()
    stage_candidate(lab)
    code = ("from pathlib import Path\nimport subprocess,tempfile\n"
            "from v5.core.tls.gateway import render_gateway\nfrom v5.core.tls.queue import registry\n"
            "names,ipv6=registry()\nconfig=render_gateway(names,ipv6=ipv6)\n"
            "assert 'location = /observability/history' in config\n"
            "with tempfile.TemporaryDirectory(prefix='kvn-v5-nginx-check-') as directory:\n"
            " path=Path(directory)/'nginx.conf'; path.write_text(config,encoding='utf-8')\n"
            " subprocess.run(['/usr/sbin/nginx','-t','-q','-c',str(path)],check=True,timeout=30)\n"
            "print('Новый маршрут: nginx -t успешно; конфигурация не применялась.')")
    result = lab.run(f"cd {INSTALLED}; python3 -c " + shlex.quote(code), timeout=90, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace")[-1500:])
    print(result.stdout.decode(), end="", flush=True)


if __name__ == "__main__":
    main()
