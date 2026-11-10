from __future__ import annotations

from typing import Any


def resolve_response_path(
    data: Any,
    path: str,
) -> tuple[bool, Any]:
    current = data

    for part in (part for part in path.split(".") if part):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False, None

    return True, current


def exact_target_visible(value: Any, target_id: Any) -> bool:
    if target_id is None:
        return False

    if isinstance(value, dict):
        return (
            "id" in value
            and str(value["id"]) == str(target_id)
        )

    if isinstance(value, list):
        return any(
            isinstance(item, dict)
            and "id" in item
            and str(item["id"]) == str(target_id)
            for item in value
        )

    return False


def classify_http_response(
    response,
    target_path: str,
    target_id: Any,
) -> dict:
    status = response.status_code

    if status in (401, 403):
        return {
            "outcome": "BLOCKED",
            "blocked": True,
            "target_exposed": False,
            "target_confirmed": False,
            "http_status": status,
            "detail": "HTTP authentication/authorization block",
        }

    if status < 200 or status >= 300:
        return {
            "outcome": "INCONCLUSIVE",
            "blocked": False,
            "target_exposed": False,
            "target_confirmed": False,
            "http_status": status,
            "detail": "Unexpected HTTP status",
        }

    try:
        payload = response.json()
    except (ValueError, TypeError):
        payload = None

    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("data"), dict)
    ):
        return {
            "outcome": "INCONCLUSIVE",
            "blocked": False,
            "target_exposed": False,
            "target_confirmed": False,
            "http_status": status,
            "detail": "Malformed or missing GraphQL data",
        }

    found, value = resolve_response_path(
        payload["data"],
        target_path,
    )
    errors = payload.get("errors") or []

    if not found:
        return {
            "outcome": "INCONCLUSIVE",
            "blocked": False,
            "target_exposed": False,
            "target_confirmed": False,
            "http_status": status,
            "detail": "Target response path not present",
        }

    if value is None or value == [] or value == {}:
        outcome = "INCONCLUSIVE" if errors else "NOT_EXPOSED"

        return {
            "outcome": outcome,
            "blocked": False,
            "target_exposed": False,
            "target_confirmed": False,
            "http_status": status,
            "detail": (
                "GraphQL errors prevent conclusion"
                if errors
                else "Target path empty"
            ),
        }

    confirmed = exact_target_visible(value, target_id)

    return {
        "outcome": (
            "EXPOSED_CONFIRMED"
            if confirmed
            else "POSSIBLE_EXPOSURE"
        ),
        "blocked": False,
        "target_exposed": True,
        "target_confirmed": confirmed,
        "http_status": status,
        "detail": (
            "Exact target ID returned"
            if confirmed
            else "Data returned without exact target ID confirmation"
        ),
    }
