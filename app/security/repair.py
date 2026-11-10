"""
Self-repairing configuration.

Layer 2 already records every owned object Layer 1 never evaluated. This module
turns those records into configuration repairs:

  evidence   Layer 2 notes, for each object Layer 1 missed, the field and the
             arguments that reached it, and every mutation it refused because
             no ownership target is known. Recent requests are sampled too.
  diagnosis  each gap gets a cause: an ID argument the configuration does not
             list, a mutation with no target, an owned type the configuration
             left out (from the startup lint), relationship traversal (expected,
             Layer 2 covers it), or a gap in Layer 1's own code (named, not fixed).
  repair     a configuration change for each fixable cause.
  verify     each repair is replayed offline through Layer 1 against the recorded
             requests. Nothing executes and no data changes. A repair is offered
             only when it closes gaps (or protects objects) and blocks no request
             that was legitimate.
  apply      an administrator applies or reverts a repair. Nothing is applied
             automatically. Applied repairs are stored and re-applied on startup.

Only configuration can be repaired. A bug in Layer 1's code is reported with the
query constructs involved, for a developer to fix.
"""
from __future__ import annotations

import json
import logging
import threading
from collections import Counter, defaultdict, deque
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from graphql import DocumentNode, GraphQLList, GraphQLNonNull, print_ast
from graphql.execution.values import get_argument_values

try:  # graphql-core >= 3.3
    from graphql.execution.values import VariableValues
except ImportError:  # older graphql-core takes a plain dict
    VariableValues = None

from app.database import get_db_connection
from app.security.shield_config import (
    ORIGINAL, REGISTRY, ShieldConfig, lint_config, restore_original, unwrap_type,
)

logger = logging.getLogger(__name__)

MAX_GAPS = 4000
MAX_SAMPLES = 2000
MAX_MUTATIONS = 1000
MIN_RESOLVED = 0.9          # share of IDs the owner lookup must recognise
EXAMPLES_PER_SUGGESTION = 3

_lock = threading.Lock()
GAPS: dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_GAPS))
SAMPLES: dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_SAMPLES))
UNREGISTERED: dict[str, deque] = defaultdict(lambda: deque(maxlen=MAX_MUTATIONS))


def clear_evidence(name: str | None = None) -> None:
    with _lock:
        for store in (GAPS, SAMPLES, UNREGISTERED):
            if name is None:
                store.clear()
            else:
                store.pop(name, None)


# ------------------------------------------------------------------------ evidence

def _query_text(info) -> str:
    definitions = [info.operation, *getattr(info, "fragments", {}).values()]
    return print_ast(DocumentNode(definitions=tuple(definitions)))


def _caller(info) -> dict:
    request = (info.context or {}).get("request") if isinstance(info.context, dict) else getattr(info.context, "request", None)
    user = getattr(getattr(request, "state", None), "current_user", None)
    return user if isinstance(user, dict) else {}


def _variables(info) -> dict:
    """The request's variables. graphql-core 3.3 wraps them in a VariableValues
    record (values in .coerced); older versions and Strawberry pass a dict."""
    values = getattr(info, "variable_values", None)
    values = getattr(values, "coerced", values)
    try:
        return dict(values or {})
    except (TypeError, ValueError):
        return {}


def _arguments(info) -> dict:
    try:
        field_def = info.parent_type.fields[info.field_name]
        variables = info.variable_values
        if isinstance(variables, dict) and VariableValues is not None:
            # Strawberry passes a plain dict; graphql-core 3.3 expects VariableValues.
            # Without this, arguments given as variables were silently dropped, so a
            # gap on `resource(id: $id)` looked like relationship traversal.
            variables = VariableValues(sources={}, coerced=variables)
        return get_argument_values(field_def, info.field_nodes[0], variables)
    except Exception:
        return {}


def _same_id(config: ShieldConfig, value, object_id) -> bool:
    if isinstance(value, (list, tuple)):
        return any(_same_id(config, item, object_id) for item in value)
    if value is None or isinstance(value, (dict, bool)):
        return False
    _, raw = config.decode(value)
    return str(raw) == str(object_id)


def record_gap(config: ShieldConfig, info, object_type: str, object_id, decision: str) -> None:
    """Layer 2 evaluated an owned object Layer 1 never saw."""
    try:
        arguments = _arguments(info)
        user = _caller(info)
        _, is_list = unwrap_type(info.return_type)
        gap = {
            "parent_type": info.parent_type.name,
            "field": info.field_name,
            "is_list": is_list,
            "arguments": sorted(arguments),
            "id_arguments": sorted(name for name, value in arguments.items() if _same_id(config, value, object_id)),
            "object_type": object_type,
            "object_id": object_id,
            "decision": decision,
            "user_id": user.get("user_id"),
            "role": user.get("role", "user"),
            "query": _query_text(info),
            "variables": _variables(info),
        }
    except Exception:
        logger.debug("Could not record a coverage gap", exc_info=True)
        return
    with _lock:
        GAPS[config.name].append(gap)


def record_unregistered_mutation(config: ShieldConfig, info, arguments: dict) -> None:
    """Layer 2 refused a mutation because no ownership target is known for it."""
    try:
        user = _caller(info)
        entry = {
            "mutation": info.field_name,
            "arguments": {k: v for k, v in arguments.items() if isinstance(v, (str, int, float))},
            "user_id": user.get("user_id"),
            "role": user.get("role", "user"),
            "query": _query_text(info),
            "variables": _variables(info),
        }
    except Exception:
        return
    with _lock:
        UNREGISTERED[config.name].append(entry)


def record_sample(name: str, user: dict, operations: list, status: int, layer2_denied: bool) -> None:
    """A request the gateway handled, kept so repairs can be replayed against it."""
    if not isinstance(user, dict) or not operations:
        return
    with _lock:
        for operation in operations:
            if isinstance(operation, dict) and operation.get("query"):
                SAMPLES[name].append({
                    "user_id": user.get("user_id"), "role": user.get("role", "user"),
                    "query": operation.get("query"), "variables": operation.get("variables") or {},
                    "status": status, "layer2_denied": bool(layer2_denied),
                })


# ------------------------------------------------------------------- Layer 1 replay

def _is_admin(role) -> bool:
    return str(role or "").upper() == "ADMIN"


def layer1_view(config: ShieldConfig, query: str, variables: dict, user_id, role) -> tuple[set, set]:
    """Objects Layer 1 would evaluate for a request under `config`, and those it
    would deny. Pure analysis: nothing is executed."""
    from app.security.object_extractor import normalize_query

    normalized = normalize_query(query, variables if isinstance(variables, dict) else {}, config=config) or {}
    seen, denied = set(), set()
    for obj in normalized.get("objects", []):
        key = (obj["type"], str(obj["id"]))
        seen.add(key)
        if not _is_admin(role):
            try:
                owner = config.owner_lookup(obj["type"], obj["id"])
            except Exception:
                owner = None
            if str(owner) != str(user_id):
                denied.add(key)
    return seen, denied


def _resolves(config: ShieldConfig, key: str, raw_id) -> bool:
    try:
        return config.owner_lookup(key, raw_id) is not None
    except Exception:
        return False


# ------------------------------------------------------------------------ repairs

def describe(repair: dict) -> str:
    kind, p = repair["kind"], repair["payload"]
    if kind == "add_id_argument":
        return f"Treat argument `{p['argument']}` as an object ID"
    if kind == "add_mutation_target":
        return f"Register mutation `{p['mutation']}`: target argument `{p['argument']}`, owned type `{p['key']}`"
    if kind == "add_owned_type":
        return f"Protect type `{p['type']}` as owned (ownership key `{p['key']}`)"
    return kind


def candidate_config(config: ShieldConfig, repair: dict) -> ShieldConfig:
    """A copy of `config` with the repair applied; the live configuration is untouched."""
    kind, p = repair["kind"], repair["payload"]
    if kind == "add_id_argument":
        return replace(config, id_arguments=tuple(dict.fromkeys((*config.id_arguments, p["argument"]))))
    if kind == "add_mutation_target":
        return replace(config, mutation_targets={**config.mutation_targets, p["mutation"]: (p["argument"], p["key"])})
    if kind == "add_owned_type":
        return replace(config, owned_types={**config.owned_types, p["type"]: p["key"]})
    raise ValueError(f"unknown repair kind {kind}")


def _apply_in_place(config: ShieldConfig, repair: dict) -> None:
    repaired = candidate_config(config, repair)
    for field in ("id_arguments", "mutation_targets", "owned_types"):
        setattr(config, field, getattr(repaired, field))


def _revert_in_place(config: ShieldConfig, repair: dict) -> None:
    kind, p = repair["kind"], repair["payload"]
    if kind == "add_id_argument":
        config.id_arguments = tuple(a for a in config.id_arguments if a != p["argument"])
    elif kind == "add_mutation_target":
        config.mutation_targets = {k: v for k, v in config.mutation_targets.items() if k != p["mutation"]}
    elif kind == "add_owned_type":
        config.owned_types = {k: v for k, v in config.owned_types.items() if k != p["type"]}


def _mutation_mentions(mutation: str, key: str) -> bool:
    return key.lower() in mutation.lower()


def _owned_type_keys(type_name: str, config: ShieldConfig) -> list[str]:
    stem = type_name[:-4] if type_name.endswith("Type") and len(type_name) > 4 else type_name
    keys = [stem, type_name]
    for original in ORIGINAL.get(config.name, {}).get("owned_types", {}).values():
        if original not in keys:
            keys.append(original)
    return list(dict.fromkeys(keys))


# ----------------------------------------------------------------------- analysis

def _replay_set(name: str) -> list[dict]:
    """Recorded requests, without duplicates: samples first, then gap requests."""
    seen, replay = set(), []
    with _lock:
        rows = [*({**s, "source": "sample"} for s in SAMPLES[name]),
                *({**g, "source": "gap"} for g in GAPS[name]),
                *({**m, "source": "mutation"} for m in UNREGISTERED[name])]
    for row in rows:
        key = (row.get("user_id"), row.get("role"), row["query"], json.dumps(row.get("variables"), sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            replay.append(row)
    return replay


def verify(config: ShieldConfig, repair: dict) -> dict:
    """Replay the recorded requests through Layer 1 with and without the repair."""
    repaired = candidate_config(config, repair)
    with _lock:
        gaps = list(GAPS[config.name])
        mutations = list(UNREGISTERED[config.name])
    replay = _replay_set(config.name)

    gaps_closed = attacks_blocked_earlier = 0
    for gap in gaps:
        target = (gap["object_type"], str(gap["object_id"]))
        before, _ = layer1_view(config, gap["query"], gap["variables"], gap["user_id"], gap["role"])
        after, _ = layer1_view(repaired, gap["query"], gap["variables"], gap["user_id"], gap["role"])
        if target in after and target not in before:
            gaps_closed += 1
            attacks_blocked_earlier += gap["decision"] == "DENY"

    false_blocks = newly_checked = resolved = exposures = 0
    examples_blocked = []
    for row in replay:
        before_seen, before_denied = layer1_view(config, row["query"], row["variables"], row["user_id"], row["role"])
        after_seen, after_denied = layer1_view(repaired, row["query"], row["variables"], row["user_id"], row["role"])
        new = after_seen - before_seen
        newly_checked += len(new)
        resolved += sum(_resolves(repaired, key, raw) for key, raw in new)
        newly_denied = after_denied - before_denied
        if not newly_denied:
            continue
        legitimate = (row["source"] == "sample" and row.get("status") == 200 and not row.get("layer2_denied")
                      and repair["kind"] != "add_owned_type")
        if legitimate:
            false_blocks += 1
        elif repair["kind"] == "add_owned_type":
            exposures += 1
            if len(examples_blocked) < EXAMPLES_PER_SUGGESTION:
                examples_blocked.append(row["query"])

    owners_unblocked = non_owners_denied = 0
    if repair["kind"] == "add_mutation_target":
        for entry in mutations:
            if entry["mutation"] != repair["payload"]["mutation"]:
                continue
            _, denied = layer1_view(repaired, entry["query"], entry["variables"], entry["user_id"], entry["role"])
            if denied:
                non_owners_denied += 1
            else:
                owners_unblocked += 1

    resolution = resolved / newly_checked if newly_checked else 0.0
    benefit = gaps_closed + owners_unblocked + non_owners_denied + exposures
    key_conflict = None
    if repair["kind"] == "add_owned_type":
        benefit = newly_checked
        # An ownership key names one owner table. A key another owned type already
        # uses cannot be told apart by replay when IDs coincide across tables, so it
        # is refused outright.
        key_conflict = next((t for t, k in config.owned_types.items()
                             if k == repair["payload"]["key"] and t != repair["payload"]["type"]), None)
    verified = benefit > 0 and false_blocks == 0 and resolution >= MIN_RESOLVED and key_conflict is None
    return {
        "verified": verified,
        "replayed_requests": len(replay),
        "gaps_closed": gaps_closed,
        "attacks_blocked_earlier": attacks_blocked_earlier,
        "owners_unblocked": owners_unblocked,
        "non_owners_still_denied": non_owners_denied,
        "objects_newly_checked": newly_checked,
        "owner_lookup_resolution": round(resolution, 3),
        "exposures_found": exposures,
        "false_blocks": false_blocks,
        "key_used_by": key_conflict,
        "examples_now_blocked": examples_blocked,
    }


def _id_argument_candidates(config: ShieldConfig, gaps: list) -> tuple[list, list]:
    repairs, explanations = [], []
    groups: dict[tuple, list] = defaultdict(list)
    for gap in gaps:
        groups[(gap["parent_type"], gap["field"])].append(gap)
    by_argument: dict[str, list] = defaultdict(list)
    for (parent, field), items in groups.items():
        unlisted = Counter(arg for gap in items for arg in gap["id_arguments"] if arg not in config.id_arguments)
        if unlisted:
            argument, _ = unlisted.most_common(1)[0]
            by_argument[argument].extend(items)
            continue
        listed = [gap for gap in items if gap["id_arguments"]]
        if listed:
            explanations.append(_code_gap_explanation(parent, field, listed))
        else:
            explanations.append({
                "kind": "relationship_traversal", "field": f"{parent}.{field}", "count": len(items),
                "attacks": sum(g["decision"] == "DENY" for g in items),
                "explanation": "Objects reached through a relationship carry no ID in the query, so Layer 1 cannot see "
                               "them by design. Layer 2 checks each one. No configuration change is needed.",
            })
    for argument, items in by_argument.items():
        repairs.append({
            "kind": "add_id_argument", "payload": {"argument": argument},
            "evidence": {"gaps": len(items), "attacks": sum(g["decision"] == "DENY" for g in items),
                         "fields": sorted({f"{g['parent_type']}.{g['field']}" for g in items}),
                         "examples": [g["query"] for g in items[:EXAMPLES_PER_SUGGESTION]]},
            "why": f"Layer 2 found objects whose ID was passed in argument `{argument}`, which the configuration "
                   f"does not list as an ID argument, so Layer 1 never checked them.",
        })
    return repairs, explanations


def _code_gap_explanation(parent: str, field: str, gaps: list) -> dict:
    from app.security.query_features import extract_features

    constructs = Counter()
    for gap in gaps[:50]:
        features = extract_features(gap["query"], gap["variables"], batch_size=1, caller_is_admin=False) or {}
        for name in ("variable_default_count", "variable_count", "fragment_spread_count", "inline_fragment_count",
                     "alias_count", "directive_count", "nested_id_lookup_count"):
            if features.get(name):
                constructs[name] += 1
    return {
        "kind": "layer1_code_gap", "field": f"{parent}.{field}", "count": len(gaps),
        "attacks": sum(g["decision"] == "DENY" for g in gaps),
        "constructs": [name for name, _ in constructs.most_common(3)],
        "examples": [g["query"] for g in gaps[:EXAMPLES_PER_SUGGESTION]],
        "explanation": "The ID argument is configured, yet Layer 1 did not evaluate it. That points at Layer 1's "
                       "code, not its configuration; the constructs these requests share are listed for a developer.",
    }


def _mutation_candidates(config: ShieldConfig, entries: list) -> list:
    repairs = []
    by_mutation: dict[str, list] = defaultdict(list)
    for entry in entries:
        by_mutation[entry["mutation"]].append(entry)
    keys = sorted(set(config.owned_types.values()))
    for mutation, calls in by_mutation.items():
        if mutation in config.mutation_targets or mutation in config.unguarded_mutations:
            continue
        scores = Counter()
        for call in calls:
            for argument, value in call["arguments"].items():
                embedded, raw = config.decode(value)
                for key in keys:
                    if embedded is not None and embedded != key:
                        continue
                    if _resolves(config, key, raw):
                        scores[(argument, key)] += 1
        if not scores:
            continue
        best = max(scores.items(), key=lambda item: (item[1], _mutation_mentions(mutation, item[0][1]),
                                                       item[0][0].lower().endswith("id")))
        (argument, key), hits = best
        repairs.append({
            "kind": "add_mutation_target", "payload": {"mutation": mutation, "argument": argument, "key": key},
            "evidence": {"refused_calls": len(calls), "calls_resolved": hits,
                         "examples": [c["query"] for c in calls[:EXAMPLES_PER_SUGGESTION]]},
            "why": f"Layer 2 refused every call to `{mutation}` because no ownership target is known for it. In the "
                   f"recorded calls, argument `{argument}` names an existing `{key}` object.",
        })
    return repairs


def _owned_type_candidates(config: ShieldConfig) -> list:
    repairs = []
    try:
        findings = lint_config(config)
    except Exception:
        return repairs
    types = {f["type"] for f in findings if f["kind"] in ("possible_unowned_type", "unowned_id_lookup")}
    for type_name in sorted(types):
        if type_name in config.owned_types:
            continue
        best = None
        for key in _owned_type_keys(type_name, config):
            repair = {"kind": "add_owned_type", "payload": {"type": type_name, "key": key}}
            check = verify(config, repair)
            if check["objects_newly_checked"] and (best is None or check["owner_lookup_resolution"] > best[1]["owner_lookup_resolution"]):
                best = (repair, check)
            if check["verified"]:
                break
        if best is None:
            continue
        repair, check = best
        reasons = sorted({f["field"] for f in findings if f["type"] == type_name})
        repair.update({
            "evidence": {"lint": reasons, "objects_seen": check["objects_newly_checked"]},
            "why": f"`{type_name}` looks like a per-user type ({', '.join(reasons)}) but the configuration does not "
                   f"protect it, so neither layer checks who owns it.",
            "verification": check,
        })
        repairs.append(repair)
    return repairs


SEVERITY = {"add_owned_type": 0, "add_id_argument": 1, "add_mutation_target": 2}


def analyse(config: ShieldConfig) -> dict:
    """Repairs (verified first, most severe first) and explanations for a configuration."""
    with _lock:
        gaps = list(GAPS[config.name])
        mutations = list(UNREGISTERED[config.name])
        sample_count = len(SAMPLES[config.name])
    repairs = _owned_type_candidates(config)
    id_repairs, explanations = _id_argument_candidates(config, gaps)
    repairs += id_repairs + _mutation_candidates(config, mutations)
    for repair in repairs:
        repair.setdefault("verification", verify(config, repair))
        repair["title"] = describe(repair)
        repair["id"] = repair_id(config.name, repair)
    repairs.sort(key=lambda r: (not r["verification"]["verified"], SEVERITY[r["kind"]],
                                -(r["verification"]["gaps_closed"] + r["verification"]["objects_newly_checked"])))
    return {"config": config.name, "evidence": {"gaps": len(gaps), "refused_mutations": len(mutations),
                                                "sampled_requests": sample_count},
            "repairs": repairs, "explanations": explanations}


def repair_id(name: str, repair: dict) -> str:
    return f"{name}:{repair['kind']}:{json.dumps(repair['payload'], sort_keys=True)}"


# -------------------------------------------------------------- apply and persist

def init_repair_tables(cursor) -> None:
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS config_repairs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            config TEXT NOT NULL,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT NOT NULL,
            verification TEXT,
            applied_by TEXT,
            applied_at TEXT,
            reverted_at TEXT
        )
    """)


def _drop_resolved_evidence(config: ShieldConfig) -> None:
    """After a repair, forget gaps Layer 1 now sees and refusals the configuration
    now covers. Otherwise old evidence is re-read against the repaired configuration
    and misreported (for example, as a Layer 1 code gap)."""
    with _lock:
        gaps = list(GAPS[config.name])
        mutations = list(UNREGISTERED[config.name])
    still_open = []
    for gap in gaps:
        try:
            seen, _ = layer1_view(config, gap["query"], gap["variables"], gap["user_id"], gap["role"])
        except Exception:
            seen = set()
        if (gap["object_type"], str(gap["object_id"])) not in seen:
            still_open.append(gap)
    open_mutations = [m for m in mutations if m["mutation"] not in config.mutation_targets]
    with _lock:
        GAPS[config.name].clear(); GAPS[config.name].extend(still_open)
        UNREGISTERED[config.name].clear(); UNREGISTERED[config.name].extend(open_mutations)


def apply_repair(name: str, kind: str, payload: dict, applied_by) -> dict:
    """Re-verify a repair against the current evidence, then apply and store it."""
    config = REGISTRY.get(name)
    if config is None:
        raise KeyError(f"unknown configuration {name}")
    repair = {"kind": kind, "payload": payload}
    check = verify(config, repair)
    if not check["verified"]:
        raise ValueError("The repair did not pass verification against the recorded requests.")
    _apply_in_place(config, repair)
    _drop_resolved_evidence(config)
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO config_repairs (config, kind, payload, status, verification, applied_by, applied_at) "
            "VALUES (?, ?, ?, 'applied', ?, ?, ?)",
            (name, kind, json.dumps(payload, sort_keys=True), json.dumps(check), str(applied_by),
             datetime.now(timezone.utc).isoformat(timespec="seconds")))
        conn.commit()
        repair_row = cursor.lastrowid
    finally:
        conn.close()
    logger.warning("Configuration %s repaired by %s: %s", name, applied_by, describe(repair))
    return {"id": repair_row, "title": describe(repair), "verification": check}


def revert_repair(row_id: int) -> dict:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM config_repairs WHERE id = ? AND status = 'applied'", (row_id,)).fetchone()
        if row is None:
            raise KeyError("no applied repair with that id")
        config = REGISTRY.get(row["config"])
        repair = {"kind": row["kind"], "payload": json.loads(row["payload"])}
        if config is not None:
            _revert_in_place(config, repair)
        conn.execute("UPDATE config_repairs SET status = 'reverted', reverted_at = ? WHERE id = ?",
                     (datetime.now(timezone.utc).isoformat(timespec="seconds"), row_id))
        conn.commit()
    finally:
        conn.close()
    return {"id": row_id, "title": describe(repair), "reverted": True}


def applied_repairs() -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM config_repairs ORDER BY id DESC LIMIT 50").fetchall()
    except Exception:
        return []
    finally:
        conn.close()
    result = []
    for row in rows:
        repair = {"kind": row["kind"], "payload": json.loads(row["payload"])}
        result.append({"id": row["id"], "config": row["config"], "title": describe(repair), "status": row["status"],
                       "applied_by": row["applied_by"], "applied_at": row["applied_at"], "reverted_at": row["reverted_at"],
                       "verification": json.loads(row["verification"] or "{}")})
    return result


def reapply_stored_repairs() -> int:
    """On startup, apply every stored repair that is still marked applied."""
    count = 0
    for row in applied_repairs():
        if row["status"] != "applied":
            continue
        config = REGISTRY.get(row["config"])
        conn = get_db_connection()
        try:
            stored = conn.execute("SELECT kind, payload FROM config_repairs WHERE id = ?", (row["id"],)).fetchone()
        finally:
            conn.close()
        if config is not None and stored is not None:
            _apply_in_place(config, {"kind": stored["kind"], "payload": json.loads(stored["payload"])})
            count += 1
    return count


# --------------------------------------------- configuration mistakes for demos

def _demo_faults() -> dict:
    """Configuration mistakes a developer could plausibly make, used by the
    evaluation and by the dashboard's demonstration switch."""
    return {
        "demo": {
            "wrong_id_argument_name": ("id_arguments", ("objectId",), {"kind": "add_id_argument", "payload": {"argument": "id"}}),
            "missing_delete_target": ("mutation_targets", "without:deleteResource",
                                      {"kind": "add_mutation_target", "payload": {"mutation": "deleteResource", "argument": "id", "key": "Resource"}}),
            "missing_resource_type": ("owned_types", "without:ResourceType",
                                      {"kind": "add_owned_type", "payload": {"type": "ResourceType", "key": "Resource"}}),
            "missing_user_type": ("owned_types", "without:UserType",
                                  {"kind": "add_owned_type", "payload": {"type": "UserType", "key": "User"}}),
        },
        "clinic": {
            "missing_id_argument": ("id_arguments", (), {"kind": "add_id_argument", "payload": {"argument": "id"}}),
            "missing_create_record_target": ("mutation_targets", "without:createRecord",
                                             {"kind": "add_mutation_target", "payload": {"mutation": "createRecord", "argument": "patientId", "key": "Patient"}}),
            "missing_delete_prescription_target": ("mutation_targets", "without:deletePrescription",
                                                   {"kind": "add_mutation_target", "payload": {"mutation": "deletePrescription", "argument": "id", "key": "Prescription"}}),
            "missing_patient_type": ("owned_types", "without:Patient",
                                     {"kind": "add_owned_type", "payload": {"type": "Patient", "key": "Patient"}}),
            "missing_record_type": ("owned_types", "without:Record",
                                    {"kind": "add_owned_type", "payload": {"type": "Record", "key": "Record"}}),
            "missing_prescription_type": ("owned_types", "without:Prescription",
                                          {"kind": "add_owned_type", "payload": {"type": "Prescription", "key": "Prescription"}}),
        },
    }


FAULTS = _demo_faults()


def inject_fault(name: str, fault: str) -> dict:
    """Break a live configuration in one realistic way. Returns the expected repair."""
    config = REGISTRY[name]
    field, change, expected = FAULTS[name][fault]
    restore_original(config)
    if isinstance(change, str) and change.startswith("without:"):
        removed = change.split(":", 1)[1]
        setattr(config, field, {k: v for k, v in getattr(config, field).items() if k != removed})
    else:
        setattr(config, field, change)
    clear_evidence(name)
    return expected


def restore(name: str) -> None:
    restore_original(REGISTRY[name])
    clear_evidence(name)
