"""RPC root-only резервного копирования."""

from types import MappingProxyType

from .contract import HandlerSpec


def handlers(dispatcher):
    return MappingProxyType({
        "backup.list": HandlerSpec(dispatcher._backup_list, False, frozenset()),
        "project.backup": HandlerSpec(dispatcher._project_backup, True, frozenset()),
    })
