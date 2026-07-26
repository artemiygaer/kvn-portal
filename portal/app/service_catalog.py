"""Единый безопасный каталог сервисов и клиентских артефактов портала."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class ServiceGuide:
    """Краткая операторская справка без runtime-значений и секретов."""

    key: str
    label: str
    category: str
    purpose: str
    ports: tuple[str, ...]
    clients: tuple[str, ...]
    credential_scope: str
    sni_scope: str
    apply_behavior: str
    diagnostics: str
    limitations: tuple[str, ...] = ()
    managed_service: str = ""
    host_service: bool = False
    actions: tuple[str, ...] = ()
    docker_dashboard: bool = False
    protocol_dashboard: bool = False
    default_user_enabled: bool = False
    user_sni: bool = False


@dataclass(frozen=True, slots=True)
class GuidanceTopic:
    """Переиспользуемое пояснение для связанных настроек."""

    title: str
    summary: str
    details: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FileKindGuide:
    """Расположение клиентского файла в UI и способ preview."""

    group: str
    qr: bool = False


SYSTEM_ORDER = (
    "tls",
    "reality-xhttp",
    "reality-tcp",
    "hysteria",
    "telemt",
    "mtg",
    "amneziawg",
    "wireguard",
    "ocserv",
)

MANAGED_SERVICE_ORDER = (
    "nginx",
    "portal",
    "agent",
    "xray",
    "hysteria",
    "telemt",
    "mtg",
    "ocserv",
    "amneziawg",
    "wireguard",
)


_SERVICE_GUIDES = (
    ServiceGuide(
        key="tls",
        label="VLESS TLS",
        category="system",
        purpose="VLESS с обычным TLS; резервный вариант для сетей, где TLS-трафик не ограничивается.",
        ports=("443/tcp через nginx", "2443/tcp прямой резерв"),
        clients=("HAPP", "Karing", "Xray-совместимые клиенты"),
        credential_scope="UUID пользователя",
        sni_scope="SNI пользователя; сертификат должен совпадать",
        apply_behavior="Render профилей, reload nginx и restart Xray только при изменении их конфигурации.",
        diagnostics="docker compose ps nginx xray",
        limitations=("Может блокироваться провайдером; Reality обычно устойчивее.",),
        managed_service="xray",
        default_user_enabled=True,
        user_sni=True,
    ),
    ServiceGuide(
        key="reality-xhttp",
        label="Reality xHTTP",
        category="system",
        purpose="Основной VLESS/Reality-профиль с XHTTP для устойчивого повседневного подключения.",
        ports=("443/tcp через nginx", "2444/tcp прямой резерв"),
        clients=("HAPP", "Karing", "Xray-совместимые клиенты"),
        credential_scope="UUID пользователя",
        sni_scope="SNI пользователя из разрешённых aliases",
        apply_behavior="Render профилей, reload nginx и контролируемый restart Xray.",
        diagnostics="python3 tools/kvnctl.py sni-routes diagnose example.com",
        limitations=("SNI сначала добавляется в aliases, иначе nginx и Xray не будут согласованы.",),
        managed_service="xray",
        default_user_enabled=True,
        user_sni=True,
    ),
    ServiceGuide(
        key="reality-tcp",
        label="Reality TCP",
        category="system",
        purpose="Простой VLESS/Reality TCP fallback, когда XHTTP недоступен или нестабилен.",
        ports=("443/tcp через nginx", "2445/tcp прямой резерв"),
        clients=("HAPP", "Karing", "Xray-совместимые клиенты"),
        credential_scope="UUID пользователя",
        sni_scope="SNI пользователя из разрешённых aliases",
        apply_behavior="Render профилей, reload nginx и контролируемый restart Xray.",
        diagnostics="python3 tools/kvnctl.py sni-routes diagnose example.com",
        limitations=("SNI должен быть согласован с route nginx и настройками Reality.",),
        managed_service="xray",
        default_user_enabled=True,
        user_sni=True,
    ),
    ServiceGuide(
        key="hysteria",
        label="Hysteria 2",
        category="system",
        purpose="UDP-туннель для сетей, где доступен стабильный UDP/443.",
        ports=("443/udp",),
        clients=("HAPP", "Karing", "Hysteria 2"),
        credential_scope="Пароль пользователя",
        sni_scope="SNI пользователя",
        apply_behavior="Render конфигурации и restart контейнера Hysteria при изменениях.",
        diagnostics="docker compose logs --tail=100 hysteria",
        limitations=("Не работает, если оператор полностью блокирует UDP/443.",),
        managed_service="hysteria",
        actions=("start", "restart", "stop", "enable", "disable"),
        docker_dashboard=True,
        protocol_dashboard=True,
        default_user_enabled=True,
        user_sni=True,
    ),
    ServiceGuide(
        key="telemt",
        label="Telemt",
        category="system",
        purpose="Персональный MTProto proxy для Telegram с отдельным secret пользователя.",
        ports=("443/tcp через nginx SNI", "2446/tcp прямой резерв"),
        clients=("Telegram",),
        credential_scope="Secret пользователя",
        sni_scope="SNI уровня сервиса",
        apply_behavior="Обновление config.toml; обычно применяется file watcher/reload без общего restart.",
        diagnostics="docker compose logs --tail=100 telemt",
        limitations=("Смена service SNI должна одновременно обновить nginx route и Telemt.",),
        managed_service="telemt",
        actions=("start", "reload", "restart", "stop", "enable", "disable"),
        docker_dashboard=True,
        protocol_dashboard=True,
        default_user_enabled=True,
    ),
    ServiceGuide(
        key="mtg",
        label="MTProto FakeTLS",
        category="system",
        purpose="Общий MTProto FakeTLS proxy для Telegram как альтернативный транспорт.",
        ports=("443/tcp через nginx SNI", "2447/tcp прямой резерв"),
        clients=("Telegram",),
        credential_scope="Общий secret сервиса",
        sni_scope="SNI уровня сервиса",
        apply_behavior="Render config.toml и restart контейнера mtg при изменениях.",
        diagnostics="docker compose logs --tail=100 mtg",
        limitations=("Shared secret не позволяет точно атрибутировать трафик отдельному пользователю.",),
        managed_service="mtg",
        actions=("start", "restart", "stop", "enable", "disable"),
        docker_dashboard=True,
        protocol_dashboard=True,
        default_user_enabled=True,
    ),
    ServiceGuide(
        key="amneziawg",
        label="AmneziaWG",
        category="system",
        purpose="Обфусцированный WireGuard-совместимый туннель только для приложения AmneziaWG.",
        ports=("51820/udp",),
        clients=("AmneziaWG app",),
        credential_scope="Ключи peer пользователя",
        sni_scope="Не используется",
        apply_behavior="Peer-only изменения через syncconf; structural delta — controlled restart kvn-amneziawg.",
        diagnostics="python3 tools/kvnctl.py amneziawg verify",
        limitations=(
            "Не импортировать в официальный WireGuard или Karing.",
            "Конфиг awg0 нельзя подменять профилем стандартного wg0.",
        ),
        managed_service="amneziawg",
        host_service=True,
        actions=("start", "apply", "restart", "stop", "enable", "disable"),
        protocol_dashboard=True,
    ),
    ServiceGuide(
        key="wireguard",
        label="WireGuard",
        category="system",
        purpose="Стандартный WireGuard на отдельном интерфейсе wg0.",
        ports=("51821/udp",),
        clients=("Официальный WireGuard", "Karing — отдельный Clash-профиль"),
        credential_scope="Ключи peer пользователя",
        sni_scope="Не используется",
        apply_behavior="Peer-only изменения через syncconf; structural delta — controlled restart kvn-wireguard.",
        diagnostics="python3 tools/kvnctl.py wireguard verify",
        limitations=(
            "Не использовать endpoint AmneziaWG 51820/udp.",
            "Профиль Karing выдаётся отдельно от HAPP/Karing VLESS-подписки.",
        ),
        managed_service="wireguard",
        host_service=True,
        actions=("start", "apply", "restart", "stop", "enable", "disable"),
        protocol_dashboard=True,
    ),
    ServiceGuide(
        key="ocserv",
        label="OpenConnect",
        category="system",
        purpose="Отдельный AnyConnect/OpenConnect VPN-профиль с паролем пользователя.",
        ports=("443/tcp через nginx SNI", "4443/udp DTLS", "2448/tcp прямой резерв"),
        clients=("OpenConnect", "Cisco AnyConnect-совместимые клиенты"),
        credential_scope="Пароль пользователя",
        sni_scope="SNI уровня сервиса",
        apply_behavior="Render users/config и reload ocserv; restart только при structural delta.",
        diagnostics="docker compose logs --tail=100 ocserv",
        limitations=("Выдаётся отдельным файлом и не входит в HAPP/Karing подписки.",),
        managed_service="ocserv",
        actions=("start", "reload", "restart", "stop", "enable", "disable"),
        docker_dashboard=True,
        protocol_dashboard=True,
    ),
    ServiceGuide(
        key="xray",
        label="Xray",
        category="backend",
        purpose="Backend для VLESS TLS, Reality xHTTP и Reality TCP.",
        ports=("2443-2445/tcp прямые резервы", "внутренние listeners за nginx"),
        clients=("HAPP", "Karing", "Xray-совместимые клиенты"),
        credential_scope="UUID пользователей",
        sni_scope="По соответствующим VLESS/Reality профилям",
        apply_behavior="Контролируемый restart только после изменения Xray-конфигурации.",
        diagnostics="docker compose logs --tail=100 xray",
        limitations=("Публичный 443/tcp маршрутизирует nginx, а не сам контейнер Xray.",),
        managed_service="xray",
        actions=("start", "restart", "stop", "enable", "disable"),
        docker_dashboard=True,
        protocol_dashboard=True,
    ),
    ServiceGuide(
        key="nginx",
        label="nginx SNI-router",
        category="operator",
        purpose="Публичная TCP-точка входа, SNI-маршрутизация, сайт и HTTPS-подписки.",
        ports=("80/tcp", "443/tcp", "2096/tcp резерв подписок"),
        clients=("Браузер", "HAPP/Karing", "TCP VPN/proxy клиенты"),
        credential_scope="Не хранит пользовательские credentials",
        sni_scope="Aliases и default routes всех TCP-сервисов",
        apply_behavior="Проверка конфигурации и hot reload; restart только при недоступном reload.",
        diagnostics="docker compose exec nginx nginx -t",
        limitations=("Пересекающиеся SNI должны отклоняться до применения.",),
        managed_service="nginx",
        actions=("start", "reload", "restart", "enable"),
        docker_dashboard=True,
    ),
    ServiceGuide(
        key="portal",
        label="Web-портал",
        category="operator",
        purpose="HTTPS-интерфейс управления без прямого доступа к Docker socket.",
        ports=("Отдельный portal.port/tcp",),
        clients=("Современный браузер",),
        credential_scope="Login/password администратора и portal session",
        sni_scope="Домен портала или IP SAN в IP-режиме",
        apply_behavior="Hot reload приложения; VPN-сервисы не перезапускаются без отдельного плана.",
        diagnostics="python3 tools/kvnctl.py portal status",
        limitations=("В IP-режиме нужен отдельный HTTPS-порт и сертификат с совпадающим IP SAN.",),
        managed_service="portal",
        actions=("start", "reload", "restart", "enable"),
        docker_dashboard=True,
    ),
    ServiceGuide(
        key="agent",
        label="Portal agent",
        category="operator",
        purpose="Allowlisted привилегированные операции портала через Unix socket.",
        ports=("Только Unix socket",),
        clients=("Web-портал",),
        credential_scope="Токен связи portal ↔ agent",
        sni_scope="Не используется",
        apply_behavior="Reload/restart systemd-службы отдельно от VPN-контейнеров.",
        diagnostics="journalctl -u kvn-portal-agent.service -n 100 --no-pager",
        limitations=("Docker socket порталу не монтируется; произвольные RPC запрещены.",),
        managed_service="agent",
        host_service=True,
        actions=("reload", "restart"),
    ),
)

SERVICE_CATALOG = MappingProxyType({
    guide.key: guide
    for guide in _SERVICE_GUIDES
})

SYSTEM_CATALOG = tuple(SERVICE_CATALOG[key] for key in SYSTEM_ORDER)
MANAGED_SERVICE_CATALOG = tuple(
    SERVICE_CATALOG[key]
    for key in MANAGED_SERVICE_ORDER
)

GUIDANCE_TOPICS = MappingProxyType({
    "wireguard-pair": GuidanceTopic(
        title="WireGuard и AmneziaWG — разные профили",
        summary="AmneziaWG app использует awg0/51820, стандартный WireGuard и Karing — wg0/51821.",
        details=(
            "QR AmneziaWG открывайте только в AmneziaWG app.",
            "Karing получает отдельный стандартный WireGuard/Clash-профиль.",
        ),
    ),
    "happ-karing": GuidanceTopic(
        title="HAPP, Karing и резервные файлы",
        summary="HAPP/Karing получают VLESS и Hysteria по подписке; WireGuard и OpenConnect выдаются отдельно.",
        details=(
            "IP ZIP доступен без IP SAN, но HTTPS URL подписки остаётся доменным.",
            "Не обещайте IP-подписку, пока route и сертификат с точным IP SAN не готовы.",
        ),
    ),
    "domain-ip": GuidanceTopic(
        title="Домен или публичный IP",
        summary="Выбор IP меняет endpoint клиента, но не подменяет Reality SNI и имя сертификата.",
        details=(
            "IP fallback полезен при сбое DNS.",
            "HTTPS-подписки по IP разрешаются только при готовом route и совпадающем IP SAN.",
        ),
    ),
    "reality-sni": GuidanceTopic(
        title="Reality SNI",
        summary="Per-user SNI выбирается только из заранее согласованных aliases.",
        details=(
            "Одинаковое значение должно использоваться в nginx route, Xray и клиентском профиле.",
            "Диагностика SNI не гарантирует доступность у другого мобильного оператора.",
        ),
    ),
    "telegram-pair": GuidanceTopic(
        title="Telemt и MTG",
        summary="Telemt использует secret пользователя, MTG — общий secret сервиса.",
        details=(
            "SNI обоих proxy задаётся на уровне сервиса.",
            "Для MTG точная пользовательская атрибуция недоступна.",
        ),
    ),
})

FILE_KIND_CATALOG = MappingProxyType({
    "amneziawg-qr": FileKindGuide("tunnels", qr=True),
    "amneziawg-config": FileKindGuide("tunnels"),
    "wireguard-qr": FileKindGuide("tunnels", qr=True),
    "wireguard-config": FileKindGuide("tunnels"),
    "happ-qr": FileKindGuide("subscriptions", qr=True),
    "happ-url": FileKindGuide("subscriptions"),
    "karing-qr": FileKindGuide("subscriptions", qr=True),
    "karing-url": FileKindGuide("subscriptions"),
    "karing-wireguard-qr": FileKindGuide("subscriptions", qr=True),
    "karing-wireguard-url": FileKindGuide("subscriptions"),
    "karing-wireguard-config": FileKindGuide("subscriptions"),
    "telemt-qr": FileKindGuide("telegram", qr=True),
    "telemt-config": FileKindGuide("telegram"),
    "mtg-qr": FileKindGuide("telegram", qr=True),
    "mtg-config": FileKindGuide("telegram"),
    "telegram-proxy": FileKindGuide("telegram"),
    "openconnect-config": FileKindGuide("openconnect"),
})


def service_guide(key: str) -> ServiceGuide | None:
    """Возвращает только статическую справку по известному ключу."""

    return SERVICE_CATALOG.get(key)


def system_label(system: str) -> str:
    """Человекочитаемое имя system с безопасным fallback."""

    guide = SERVICE_CATALOG.get(system)
    return guide.label if guide else system


def client_file_group(kind: str) -> str:
    """Группа клиентского файла; неизвестные kinds остаются в «прочих»."""

    guide = FILE_KIND_CATALOG.get(kind)
    return guide.group if guide else "other"


def is_qr_file(kind: str) -> bool:
    """Разрешён ли inline QR-preview для известного file kind."""

    guide = FILE_KIND_CATALOG.get(kind)
    return bool(guide and guide.qr)


def validate_service_catalog() -> None:
    """Fail-closed проверка покрытия и критичных WireGuard-инвариантов."""

    if set(SYSTEM_ORDER) != {
        "tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt",
        "mtg", "amneziawg", "wireguard", "ocserv",
    }:
        raise RuntimeError("Каталог должен покрывать ровно девять systems.")
    if not set(SYSTEM_ORDER).issubset(SERVICE_CATALOG):
        raise RuntimeError("В каталоге отсутствует system.")
    if not {"portal", "nginx", "agent"}.issubset(SERVICE_CATALOG):
        raise RuntimeError("В каталоге отсутствует операторский сервис.")
    if set(MANAGED_SERVICE_ORDER) != {
        guide.key for guide in MANAGED_SERVICE_CATALOG
    }:
        raise RuntimeError("Managed service catalog рассинхронизирован.")
    for guide in SERVICE_CATALOG.values():
        if not all(
            isinstance(items, tuple)
            for items in (guide.ports, guide.clients, guide.limitations)
        ):
            raise RuntimeError(f"Списочные поля должны быть tuple: {guide.key}")
        if not all((
            guide.label,
            guide.purpose,
            guide.ports,
            guide.clients,
            guide.credential_scope,
            guide.sni_scope,
            guide.apply_behavior,
            guide.diagnostics,
        )):
            raise RuntimeError(f"Неполная справка сервиса: {guide.key}")
    amnezia = SERVICE_CATALOG["amneziawg"]
    wireguard = SERVICE_CATALOG["wireguard"]
    if any("Karing" in client or "WireGuard" == client for client in amnezia.clients):
        raise RuntimeError("AmneziaWG нельзя предлагать WireGuard/Karing.")
    if any("51820" in port for port in wireguard.ports):
        raise RuntimeError("Стандартный WireGuard не должен указывать 51820.")
    if not any("51821" in port for port in wireguard.ports):
        raise RuntimeError("Стандартный WireGuard должен указывать 51821.")
    if "IP SAN" not in " ".join(GUIDANCE_TOPICS["happ-karing"].details):
        raise RuntimeError("HAPP/Karing help должен объяснять certificate gate.")


validate_service_catalog()
