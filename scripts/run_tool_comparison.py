"""
Compare GraphQL Shield with graphql-shield (Node) on the same schema and data.

Both systems protect the demo schema (comparison/schema.graphql) whose
resolvers contain no ownership checks. The same scenarios run against both, and
one oracle judges every response:

  - an attack "leaks" if the response contains an object the caller does not
    own, or the victim object (102) was changed;
  - a benign request "fails" if the caller's own data is not returned.

Variants measure robustness to configuration mistakes, the common real-world
failure: each graphql-shield permission entry, and each GraphQL Shield config
entry, is removed one at a time.

    python -m scripts.run_tool_comparison

Needs Node.js and `npm install` in comparison/graphql-shield. Writes
results/tool_comparison/results.json.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient

from app.config import settings
from app.core.security import create_access_token
from app.security import shield_config
from app.security.layers import set_layers

NODE_DIR = os.path.join(PROJECT_ROOT, "comparison", "graphql-shield")
OUTPUT = os.path.join(PROJECT_ROOT, "results", "tool_comparison", "results.json")
CALLER = 101
VICTIM = 102
VICTIM_STATE = {"name": "Kapilesh's Financial Record", "ownerId": 102}
FOREIGN_RESOURCES = {102, 103, 104, 204}   # objects not owned by the caller
FIELDS = "id name ownerId"


def q(text, **extra):
    return {"query": text, **extra}


SCENARIOS = [
    # ---- attacks by user 101
    {"name": "direct", "kind": "attack", "body": q(f"{{ resource(id: {VICTIM}) {{ {FIELDS} }} }}")},
    {"name": "variable", "kind": "attack", "body": q(f"query($r: Int!) {{ resource(id: $r) {{ {FIELDS} }} }}", variables={"r": VICTIM})},
    {"name": "variable_default", "kind": "attack", "body": q(f"query($r: Int = {VICTIM}) {{ resource(id: $r) {{ {FIELDS} }} }}")},
    {"name": "alias", "kind": "attack", "body": q(f"{{ x: resource(id: {VICTIM}) {{ {FIELDS} }} }}")},
    {"name": "named_fragment", "kind": "attack", "body": q(f"query {{ ...F }} fragment F on Query {{ resource(id: {VICTIM}) {{ {FIELDS} }} }}")},
    {"name": "inline_fragment", "kind": "attack", "body": q(f"{{ ... on Query {{ resource(id: {VICTIM}) {{ {FIELDS} }} }} }}")},
    {"name": "nested_lookup", "kind": "attack", "body": q(f"{{ user(id: {CALLER}) {{ id resource(id: {VICTIM}) {{ {FIELDS} }} }} }}")},
    {"name": "foreign_user", "kind": "attack", "body": q("{ user(id: 102) { id username role } }")},
    {"name": "relationship", "kind": "attack", "body": q(f"{{ resource(id: 201) {{ id children {{ {FIELDS} }} }} }}")},
    {"name": "batch", "kind": "attack", "body": [q("{ resource(id: 101) { id } }"), q(f"{{ resource(id: {VICTIM}) {{ {FIELDS} }} }}")]},
    {"name": "update", "kind": "attack", "body": q(f'mutation {{ updateResource(id: {VICTIM}, name: "changed") {{ id }} }}')},
    {"name": "delete", "kind": "attack", "body": q(f"mutation {{ deleteResource(id: {VICTIM}) }}")},
    {"name": "transfer", "kind": "attack", "body": q(f"mutation {{ transferOwnership(id: {VICTIM}, newOwnerId: {CALLER}) {{ id }} }}")},
    # ---- benign: the caller's own data, and an administrator
    {"name": "own_direct", "kind": "benign", "expect": [101], "body": q(f"{{ resource(id: 101) {{ {FIELDS} }} }}")},
    {"name": "own_relationship", "kind": "benign", "expect": [202, 203], "body": q(f"{{ resource(id: 201) {{ id children {{ {FIELDS} }} }} }}")},
    {"name": "own_user", "kind": "benign", "expect": [101], "body": q("{ user(id: 101) { id username } }")},
    {"name": "own_update", "kind": "benign", "expect": [101], "body": q('mutation { updateResource(id: 101, name: "renamed") { id name } }')},
    {"name": "admin_relationship", "kind": "benign", "expect": [202, 203, 204], "user": 104, "role": "admin",
     "body": q(f"{{ resource(id: 201) {{ id children {{ {FIELDS} }} }} }}")},
]
for scenario in SCENARIOS:
    scenario.setdefault("user", CALLER)
    scenario.setdefault("role", "user")


# ------------------------------------------------------------------ oracle

def _objects(value):
    if isinstance(value, dict):
        if "id" in value and value["id"] is not None:
            yield value
        for child in value.values():
            yield from _objects(child)
    elif isinstance(value, list):
        for item in value:
            yield from _objects(item)


def judge(scenario, responses, victim) -> dict:
    data = [r.get("data") for r in responses if not r.get("blocked")]
    returned = list(_objects(data))
    if scenario["kind"] == "attack":
        exposed = sorted({
            (("User" if "username" in o else "Resource"), o["id"]) for o in returned
            if ("username" in o and o["id"] != scenario["user"])
            or ("username" not in o and o["id"] in FOREIGN_RESOURCES)
        })
        changed = victim != VICTIM_STATE
        return {"leaked": bool(exposed or changed), "exposed": exposed, "victim_changed": changed}
    ids = {o["id"] for o in returned}
    ok = set(scenario["expect"]) <= ids and not any(r.get("errors") or r.get("blocked") for r in responses)
    return {"ok": ok}


# ------------------------------------------------------------------ GraphQL Shield

def _victim_state(db_file):
    conn = sqlite3.connect(db_file)
    try:
        row = conn.execute("SELECT name, owner_id FROM objects WHERE id = ?", (VICTIM,)).fetchone()
        return {"name": row[0], "ownerId": row[1]} if row else None
    finally:
        conn.close()


def run_graphql_shield(variants: dict) -> dict:
    from app.seed import add_shared_folder_scenario, seed_database

    original_url = settings.DATABASE_URL
    db_file = os.path.join(tempfile.mkdtemp(prefix="shield-compare-"), "compare.db")
    settings.DATABASE_URL = f"sqlite:///{db_file}"
    config = shield_config.default_config()
    saved = (copy.deepcopy(config.owned_types), copy.deepcopy(config.mutation_targets))
    results = {}
    try:
        from app.main import app

        client = TestClient(app)
        set_layers(True, True)
        for variant, mutate in variants.items():
            config.owned_types, config.mutation_targets = copy.deepcopy(saved[0]), copy.deepcopy(saved[1])
            mutate(config)
            rows = []
            for scenario in SCENARIOS:
                seed_database()
                add_shared_folder_scenario()
                token = create_access_token(user_id=scenario["user"], role=scenario["role"])
                response = client.post("/graphql", json=scenario["body"], headers={"Authorization": f"Bearer {token}"})
                payload = response.json()
                if response.status_code == 403:
                    responses = [{"blocked": True}]
                else:
                    responses = payload if isinstance(payload, list) else [payload]
                rows.append({"scenario": scenario["name"], **judge(scenario, responses, _victim_state(db_file))})
            results[variant] = rows
    finally:
        config.owned_types, config.mutation_targets = saved
        settings.DATABASE_URL = original_url
    return results


def _without_owned(key):
    def mutate(config):
        config.owned_types = {t: k for t, k in config.owned_types.items() if k != key}
    return mutate


def _without_target(name):
    def mutate(config):
        config.mutation_targets.pop(name, None)
    return mutate


SHIELD_VARIANTS = {
    "complete": lambda config: None,
    "without owned type Resource": _without_owned("Resource"),
    "without owned type User": _without_owned("User"),
    "without mutation target updateResource": _without_target("updateResource"),
    "without mutation target deleteResource": _without_target("deleteResource"),
    "without mutation target transferOwnership": _without_target("transferOwnership"),
}


# ------------------------------------------------------------------ graphql-shield (Node)

NODE_RULES = ["Query.user", "Query.resource", "UserType.resource", "UserType.*", "ResourceType.*",
              "Mutation.updateResource", "Mutation.deleteResource", "Mutation.transferOwnership"]
NODE_VARIANTS = (["complete", "fallback_deny"]
                 + [f"without:{rule}" for rule in NODE_RULES]
                 + [f"fallback_deny,without:{rule}" for rule in NODE_RULES])


def run_node(scenario_file: str) -> dict:
    results = {}
    for variant in NODE_VARIANTS:
        output = subprocess.run(["node", "run.mjs", variant, scenario_file], cwd=NODE_DIR,
                                capture_output=True, text=True, check=True).stdout
        by_name = {s["name"]: s for s in SCENARIOS}
        results[variant] = [
            {"scenario": row["scenario"], **judge(by_name[row["scenario"]], row["responses"], row["victim"])}
            for row in json.loads(output)
        ]
    return results


# ------------------------------------------------------------------ report

def summarize(rows) -> dict:
    attacks = [r for r in rows if "leaked" in r]
    benign = [r for r in rows if "ok" in r]
    return {
        "attacks_leaked": sum(r["leaked"] for r in attacks),
        "attacks": len(attacks),
        "leaked_scenarios": [r["scenario"] for r in attacks if r["leaked"]],
        "benign_failed": sum(not r["ok"] for r in benign),
        "benign": len(benign),
        "failed_benign_scenarios": [r["scenario"] for r in benign if not r["ok"]],
    }


def main() -> None:
    logging.getLogger("strawberry.execution").setLevel(logging.CRITICAL)
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    scenario_file = os.path.join(os.path.dirname(OUTPUT), "scenarios.json")
    with open(scenario_file, "w", encoding="utf-8") as file:
        json.dump([{k: s[k] for k in ("name", "user", "role", "body")} for s in SCENARIOS], file)

    systems = {"GraphQL Shield": run_graphql_shield(SHIELD_VARIANTS), "graphql-shield": run_node(scenario_file)}
    config = shield_config.default_config()
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenarios": [{"name": s["name"], "kind": s["kind"]} for s in SCENARIOS],
        "configuration_size": {
            "GraphQL Shield": {"owned_types": len(config.owned_types), "mutation_registry_entries": len(config.mutation_targets),
                               "mutation_entries_not_derivable_from_schema": 1},
            "graphql-shield": {"permission_entries": len(NODE_RULES), "rule_functions": 4},
        },
        "systems": {name: {variant: {**summarize(rows), "rows": rows} for variant, rows in variants.items()}
                    for name, variants in systems.items()},
    }
    with open(OUTPUT, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    for name, variants in report["systems"].items():
        print(f"\n{name}")
        for variant, summary in variants.items():
            leaked = ", ".join(summary["leaked_scenarios"]) or "-"
            failed = ", ".join(summary["failed_benign_scenarios"]) or "-"
            print(f"  {variant:44} leaked {summary['attacks_leaked']:2}/{summary['attacks']}  "
                  f"benign failed {summary['benign_failed']}/{summary['benign']}  leaks: {leaked}  false blocks: {failed}")
    print(f"\nWrote {OUTPUT}")


if __name__ == "__main__":
    main()
