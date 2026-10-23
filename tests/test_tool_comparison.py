"""The tool-comparison harness: oracle behaviour and GraphQL Shield's side.
(The graphql-shield side needs Node.js and is run by the script itself.)"""
from scripts.run_tool_comparison import SCENARIOS, VICTIM_STATE, judge, run_graphql_shield, summarize

BY_NAME = {s["name"]: s for s in SCENARIOS}


def test_oracle_flags_exposed_foreign_object():
    verdict = judge(BY_NAME["direct"], [{"data": {"resource": {"id": 102, "name": "x"}}}], VICTIM_STATE)
    assert verdict["leaked"] and verdict["exposed"] == [("Resource", 102)]


def test_oracle_flags_changed_victim_even_without_data():
    verdict = judge(BY_NAME["update"], [{"data": {"updateResource": None}}], {**VICTIM_STATE, "name": "changed"})
    assert verdict["leaked"] and verdict["victim_changed"]


def test_oracle_accepts_blocked_attack():
    assert judge(BY_NAME["direct"], [{"blocked": True}], VICTIM_STATE)["leaked"] is False


def test_oracle_requires_all_own_objects_for_benign():
    partial = [{"data": {"resource": {"id": 201, "children": [{"id": 202}]}}}]
    assert judge(BY_NAME["own_relationship"], partial, VICTIM_STATE)["ok"] is False
    full = [{"data": {"resource": {"id": 201, "children": [{"id": 202}, {"id": 203}]}}}]
    assert judge(BY_NAME["own_relationship"], full, VICTIM_STATE)["ok"] is True


def test_graphql_shield_complete_config_has_no_leaks_or_false_blocks():
    summary = summarize(run_graphql_shield({"complete": lambda config: None})["complete"])
    assert summary["attacks_leaked"] == 0
    assert summary["benign_failed"] == 0


def test_missing_mutation_registry_entry_fails_closed():
    def without_delete(config):
        config.mutation_targets.pop("deleteResource")

    summary = summarize(run_graphql_shield({"variant": without_delete})["variant"])
    assert summary["attacks_leaked"] == 0
