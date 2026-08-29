"""Единое безопасное отображение ошибок host-agent в HTTP."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentHttpError:
    code: str
    status: int
    message: str


ERRORS = {
    "awg31_unsupported": AgentHttpError(
        "awg31_unsupported",
        409,
        "AWG 3.1 не поддерживается установленными awg-tools или kernel module.",
    ),
    "validation_error": AgentHttpError(
        "validation_error", 400, "Запрос отклонён проверкой данных.",
    ),
    "invalid_params": AgentHttpError(
        "invalid_params", 400, "Запрос содержит недопустимые параметры.",
    ),
    "revision_conflict": AgentHttpError(
        "revision_conflict", 409, "Данные уже изменились. Обновите страницу и повторите операцию.",
    ),
    "transport_unavailable": AgentHttpError(
        "transport_unavailable", 503, "Host-agent недоступен временно. Повторите операцию после восстановления сервиса.",
    ),
    "transport_secret_unreadable": AgentHttpError(
        "transport_secret_unreadable", 503, "Host-agent недоступен: портал не может прочитать RPC credential.",
    ),
    "transport_unsupported": AgentHttpError(
        "transport_unsupported", 503, "Unix transport host-agent недоступен в этой среде.",
    ),
    "transport_invalid_response": AgentHttpError(
        "transport_invalid_response", 502, "Host-agent вернул некорректный ответ.",
    ),
    "transport_response_mismatch": AgentHttpError(
        "transport_response_mismatch", 502, "Host-agent вернул ответ другого запроса.",
    ),
    "transport_response_too_large": AgentHttpError(
        "transport_response_too_large", 502, "Ответ host-agent превышает безопасный лимит.",
    ),
}


def map_agent_error(error) -> AgentHttpError:
    code = getattr(error, "code", "agent_error")
    return ERRORS.get(
        code,
        AgentHttpError(
            "agent_error",
            502,
            "Host-agent недоступен или отклонил операцию. Проверьте журнал сервиса.",
        ),
    )
