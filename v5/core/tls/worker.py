"""Одноразовая служба выпуска по очереди или продления по таймеру."""

import argparse
from datetime import datetime, timezone
import os

from .acme import AcmeMode
from .acme_service import AcmeError, AcmeResult, AcmeService
from .certificates import CertificateError
from .controller import GatewayController
from .queue import GATEWAY_ROOT, QueueBusy, TLSQueue, read_json, registry
from .transaction import CertificateStore, GatewayApplyError


def _format(result: AcmeResult) -> dict:
    return {"status": result.status, "expires_at": result.expires_at.isoformat() if result.expires_at else None,
            "updated_at": datetime.now(timezone.utc).isoformat()}


def run(*, renew: bool) -> None:
    queue = TLSQueue()
    try:
        with queue.exclusive():
            identities, ipv6 = registry()
            job = queue.take(identities)
            if job is None and not renew:
                return
            gateway = GatewayController(GATEWAY_ROOT / "nginx.conf", CertificateStore(GATEWAY_ROOT / "certs"),
                                        identities, ipv6=ipv6)
            service = AcmeService(gateway)
            records = read_json(queue.results, {})
            records = {item.slot: records.get(item.slot, {}) for item in identities} if isinstance(records, dict) else {}

            def record(identity, mode, result):
                entry = records.setdefault(identity.slot, {})
                if not isinstance(entry, dict):
                    entry = records[identity.slot] = {}
                entry[mode.value] = _format(result)

            if job is not None:
                try:
                    outcome = service.issue(job.identity, job.mode, job.email)
                except (AcmeError, CertificateError, GatewayApplyError) as exc:
                    outcome = AcmeResult(exc.code)
                except (OSError, ValueError):
                    outcome = AcmeResult("tls_state_error")
                record(job.identity, job.mode, outcome)
            if renew:
                for identity, outcome in service.renew_due().items():
                    record(identity, AcmeMode.PUBLIC, outcome)
                    if outcome.status == "active" and outcome.expires_at is not None:
                        print(f"TLS: сертификат {identity.authority} продлён до {outcome.expires_at.isoformat()}", flush=True)
            try:
                active = {pair.metadata.identity: pair.metadata.not_after.isoformat() for pair in gateway.active()}
            except (CertificateError, OSError, ValueError):
                active = None
            if active is not None:
                for identity in identities:
                    entry = records.setdefault(identity.slot, {})
                    if isinstance(entry, dict):
                        entry["active_expires_at"] = active.get(identity)
            queue.record(records)
    except QueueBusy:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--renew", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "TLS-служба требует root\n")
    try:
        run(renew=args.renew)
    except (OSError, ValueError, RecursionError):
        parser.exit(1, "Не удалось прочитать локальное состояние TLS\n")


if __name__ == "__main__":
    main()
