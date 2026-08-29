"""RPC сводки, метрик, здоровья и сертификатов."""

from types import MappingProxyType

from .contract import HandlerSpec


def handlers(dispatcher):
    control = dispatcher._control
    return MappingProxyType({
        "stats.containers": HandlerSpec(dispatcher._container_stats, False, frozenset()),
        "dashboard.snapshot": HandlerSpec(dispatcher._dashboard_snapshot, False, frozenset()),
        "health.host": HandlerSpec(dispatcher._host_health, False, frozenset()),
        "health.summary": HandlerSpec(dispatcher._health_summary, False, frozenset()),
        "metrics.current": HandlerSpec(dispatcher._metrics_current, False, frozenset()),
        "metrics.history": HandlerSpec(dispatcher._metrics_history, False, frozenset({"range_hours", "step"})),
        "portal.performance": HandlerSpec(dispatcher._portal_performance, False, frozenset()),
        "protocol.stats": HandlerSpec(dispatcher._protocol_stats, False, frozenset()),
        "certificates.status": HandlerSpec(lambda _p: control().certificate_status(), False, frozenset()),
        "certificate.action": HandlerSpec(dispatcher._certificate_action, True, frozenset({"action", "target"})),
        "amneziawg.status": HandlerSpec(dispatcher._awg_status, False, frozenset()),
    })
