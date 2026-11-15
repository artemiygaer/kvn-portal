# Xray в KVN v5

Начальная проверенная точка для сборки модуля — официальный [Xray-core v26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31). Манифест образа, полученный из GHCR в WSL:

- OCI index: `sha256:ceabeac03a89d991d2a247361825c1d1d2e9c91cd5dc010f298c7dc0c2f325c9`;
- Linux amd64: `sha256:db94b52238af7311f30044a1ef64e77b0edf285a302c276a7f4d7b368e6a17ab`;
- Linux arm64: `sha256:760093f4323af2220d28728c840c520a00b2b303a72baba9af30f48b476f6715`.

Core-установщик не включает образ или конфигурацию. Пакет модуля ссылается на фиксированный digest платформы либо содержит проверяемый офлайн-образ. Живые соединения на amd64 проверены отдельно в изолированной сети WSL.

Протоколы сверяются с [документацией XTLS](https://xtls.github.io/en/config/transport.html). Внешний Reality и self-steal — разные явные режимы. В self-steal цель ограничена loopback fallback сайта; Xray не обслуживает админский TCP/8443.

[Описание `listen` в Xray](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/config/inbound.md) подтверждает, что `0.0.0.0` открывает обе семьи IP. Поэтому сетевой план и проверка готовности учитывают обе; заданный явно IPv4 публикуется только на нём.

Клиентский экспорт: URI `vless://` и подписка V2Ray из этих URI, закодированных base64. [HAPP](https://www.happ.su/main/dev-docs/examples-of-links-and-parameters) документирует импорт VLESS и текстовых подписок, [Karing](https://github.com/KaringX/karing/tree/v1.2.25.2802#features) — совместимость с подписками V2Ray. [В известном случае Karing/xHTTP](https://github.com/KaringX/karing/issues/1804) разработчик рекомендовал User-Agent `v2ray`; рендер KVN не меняется от User-Agent. Проверка полей URI и соединения Xray не заменяют испытание импорта на каждой платформе клиентов.
