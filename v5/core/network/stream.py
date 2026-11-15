"""SNI-публикация на общем TCP/443; шлюз сайта остаётся запасным маршрутом."""

from .plan import SITE_BACKEND_PORT, NetworkPlan

STREAM_MODULE = "/usr/lib/nginx/modules/ngx_stream_module.so"


def render_stream(plan: NetworkPlan, *, ipv6: bool) -> str:
    """Пустой план не требует загрузки stream-модуля или отдельного listener."""
    if not plan.routes:
        return ""
    v6_mapping = f"        ~: [::1]:{SITE_BACKEND_PORT};\n" if ipv6 else ""
    v6_listen = "        listen [::]:443 ipv6only=on;\n" if ipv6 else ""
    entries = "".join(
        f'        "{item.route.sni}" {item.route.backend.nginx_address()};\n'
        for item in plan.routes
    )
    return (
        f"load_module {STREAM_MODULE};\n"
        "stream {\n"
        "    map_hash_bucket_size 512;\n"
        "    map $server_addr $kvn_site_backend {\n"
        f"        default 127.0.0.1:{SITE_BACKEND_PORT};\n"
        f"{v6_mapping}"
        "    }\n"
        "    map $ssl_preread_server_name $kvn_stream_backend {\n"
        "        default $kvn_site_backend;\n"
        f"{entries}"
        "    }\n"
        "    server {\n"
        "        listen 0.0.0.0:443;\n"
        f"{v6_listen}"
        "        ssl_preread on;\n"
        "        proxy_connect_timeout 3s;\n"
        "        proxy_timeout 10m;\n"
        "        proxy_pass $kvn_stream_backend;\n"
        "    }\n"
        "}\n"
    )
