"""Чистая модель маршрутизации SNI."""

def route_collisions(domain_to_routes: dict[str, list[tuple[str, str]]]) -> dict[str, list[tuple[str, str]]]:
    return {domain: routes for domain, routes in domain_to_routes.items() if len({dest for _, dest in routes}) > 1}

def reality_alias_allowed(default: str, aliases: list[str], selected: str) -> bool:
    return selected in dict.fromkeys([default, *aliases])

def unique_domains(*groups: list[str]) -> list[str]:
    result = []
    for group in groups:
        for domain in group:
            if domain and domain not in result:
                result.append(domain)
    return result

__all__ = ["reality_alias_allowed", "route_collisions", "unique_domains"]
