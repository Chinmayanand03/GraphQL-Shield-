from __future__ import annotations

from typing import Any


def resolve_response_path(data: Any, path: str) -> tuple[bool, Any]:
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
        return "id" in value and str(value["id"]) == str(target_id)
    if isinstance(value, list):
        return any(
            isinstance(item, dict)
            and "id" in item
            and str(item["id"]) == str(target_id)
            for item in value
        )
    return False


def classify_http_response(response, target_path: str, target_id: Any) -> dict:
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
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), dict):
        return {
            "outcome": "INCONCLUSIVE",
            "blocked": False,
            "target_exposed": False,
            "target_confirmed": False,
            "http_status": status,
            "detail": "Malformed or missing GraphQL data",
        }

    found, value = resolve_response_path(payload["data"], target_path)
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
            "detail": "Target path empty" if not errors else "GraphQL errors prevent conclusion",
        }
    confirmed = exact_target_visible(value, target_id)
    if confirmed:
        outcome = "EXPOSED_CONFIRMED"
        detail = "Exact target ID returned"
        target_exposed = True
    elif isinstance(value, list):
        # A collection can return authorized siblings while excluding the
        # requested child. Sibling data alone is not evidence that the target
        # object was exposed.
        outcome = "INCONCLUSIVE" if errors else "NOT_EXPOSED"
        detail = (
            "Target ID absent from returned collection"
            if not errors
            else "GraphQL errors prevent a conclusive collection check"
        )
        target_exposed = False
    else:
        outcome = "POSSIBLE_EXPOSURE"
        detail = "Data returned without exact target ID confirmation"
        target_exposed = True
    return {
        "outcome": outcome,
        "blocked": False,
        "target_exposed": target_exposed,
        "target_confirmed": confirmed,
        "http_status": status,
        "detail": detail,
    }
