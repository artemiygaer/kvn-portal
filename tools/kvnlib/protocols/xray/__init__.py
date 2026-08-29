"""Чистые builders и сериализация Xray без runtime side effects."""

import json

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

__all__ = ["client_entries", "facts", "render_config"]
