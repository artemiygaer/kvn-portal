"""Чистые builders и сериализация Xray без runtime side effects."""

import ipaddress
import json

LOCAL_REALITY_TARGET = "nginx:8443"
REALITY_MODES = ("external", "self-steal")

def reality_mode(route: dict) -> str:
    """Отсутствующее поле сохраняет прежний внешний режим, без миграции."""
    mode = route.get("reality_mode", "external")
    if mode not in REALITY_MODES:
        raise ValueError("Режим Reality должен быть external или self-steal.")
    return mode

def reality_target(default_sni: str, site_domains: list[str], mode: str = "external") -> str:
    """Внутренний target включается только явно; домен сам режим не меняет."""
    if mode not in REALITY_MODES:
        raise ValueError("Режим Reality не разрешён.")
    if mode == "self-steal":
        if default_sni not in site_domains:
            raise ValueError("Self-steal требует SNI собственного HTTPS-сайта.")
        try:
            ipaddress.ip_address(default_sni)
        except ValueError:
            return LOCAL_REALITY_TARGET
        raise ValueError("Self-steal требует DNS-имя сайта, а не IP.")
    return f"{default_sni}:443"

def client_entries(users: list[dict], system: str, *, flow: bool) -> list[dict]:
    result = []
    for user in users:
        if system not in user.get("systems", []):
            continue
        item = {"id": user["uuid"], "email": f"{user['name']}-{system}", "level": 0}
        if flow:
            item["flow"] = "xtls-rprx-vision"
        result.append(item)
    return result

def render_config(config: dict) -> str:
    """Стабильная сериализация готового domain config."""
    return json.dumps(config, ensure_ascii=False, indent=2) + "\n"

def facts(config: dict) -> dict:
    inbounds = config.get("inbounds", [])
    return {"inbounds": len(inbounds), "tags": [item.get("tag", "") for item in inbounds], "loglevel": config.get("log", {}).get("loglevel", "warning")}

__all__ = ["LOCAL_REALITY_TARGET", "REALITY_MODES", "client_entries", "facts", "reality_mode", "reality_target", "render_config"]
