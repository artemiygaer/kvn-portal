"""RPC настройки VPN-протоколов, SNI и сетевой топологии."""

from types import MappingProxyType

from .contract import HandlerSpec


def handlers(dispatcher):
    control = dispatcher._control
    awg = {
        "revision", "protocol_version", "content_padding_addition",
        "rekey_after_time", "rekey_timeout", "reject_after_time",
        "keepalive_timeout", "max_handshake_attempts",
        "regenerate_header_key", "random_trailers",
    }
    return MappingProxyType({
        "network.topology": HandlerSpec(dispatcher._network_topology, False, frozenset()),
        "domain.advice": HandlerSpec(dispatcher._domain_advice, False, frozenset({"zone"})),
        "sni.routes": HandlerSpec(lambda _p: control().sni_routes(), False, frozenset()),
        "sni.diagnose": HandlerSpec(lambda p: control().sni_diagnose(p), False, frozenset({"sni"})),
        "sni.apply": HandlerSpec(dispatcher._sni_apply, True, frozenset({"action", "revision", "system", "sni"})),
        "mtproto.status": HandlerSpec(dispatcher._mtproto_status, False, frozenset()),
        "mtproto.diagnose": HandlerSpec(dispatcher._mtproto_diagnose, False, frozenset({"system"})),
        "mtproto.apply": HandlerSpec(dispatcher._mtproto_apply, True, frozenset({"system", "origin", "revision"})),
        "protocol.apply": HandlerSpec(dispatcher._protocol_apply, True, frozenset({"action", "system", "mode", "revision"})),
        "amneziawg.settings": HandlerSpec(dispatcher._amneziawg_settings, False, frozenset()),
        "amneziawg.apply": HandlerSpec(dispatcher._amneziawg_apply, True, frozenset(awg)),
    })
