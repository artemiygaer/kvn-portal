"""RPC управления сервисами и разрешёнными командами обслуживания."""

from types import MappingProxyType

from .contract import HandlerSpec


def handlers(dispatcher):
    return MappingProxyType({
        "ping": HandlerSpec(dispatcher._ping, False, frozenset()),
        "service.status": HandlerSpec(dispatcher._service_status, False, frozenset({"service"})),
        "service.action": HandlerSpec(dispatcher._service_action, True, frozenset({"service", "action"})),
        "logs.tail": HandlerSpec(dispatcher._logs_tail, False, frozenset({"service", "tail", "since_minutes"})),
        "maintenance.commands": HandlerSpec(dispatcher._maintenance_command_list, False, frozenset()),
        "maintenance.run": HandlerSpec(dispatcher._maintenance_run, True, frozenset({"command", "request_id"})),
    })
