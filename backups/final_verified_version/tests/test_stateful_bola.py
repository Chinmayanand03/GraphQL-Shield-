import json

import httpx

from app.security.stateful_bola import (
    ResponseReference,
    StatefulPlan,
    StatefulStep,
    execute_stateful_plan,
)


def make_plan():
    return StatefulPlan(
        plan_id="nested-bola-001",
        steps=(
            StatefulStep(
                step_id="discover-child",
                principal_id="Alice",
                query="""
                    query Discover {
                        user(id: "U101") {
                            children {
                                id
                            }
                        }
                    }
                """,
                operation_name="Discover",
                expected_access="allowed",
                response_path="data.user.children",
            ),
            StatefulStep(
                step_id="read-child",
                principal_id="Alice",
                query="""
                    query ReadChild($id: ID!) {
                        resource(id: $id) {
                            id
                            name
                        }
                    }
                """,
                variables={
                    "id": ResponseReference(
                        step_index=0,
                        json_path="data.user.children.0.id",
                    )
                },
                operation_name="ReadChild",
                expected_access="denied",
                response_path="data.resource",
                target_id_variable="id",
            ),
        ),
    )


def make_transport(expose_child=False, empty_children=False):
    def handler(request):
        body = json.loads(request.content.decode("utf-8"))
        operation = body.get("operationName")

        if operation == "Discover":
            children = [] if empty_children else [{"id": 301}]

            return httpx.Response(
                200,
                json={"data": {"user": {"children": children}}},
            )

        if operation == "ReadChild":
            if expose_child:
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "resource": {
                                "id": body["variables"]["id"],
                                "name": "Synthetic child",
                            }
                        }
                    },
                )

            return httpx.Response(
                403,
                json={"detail": "Forbidden"},
            )

        return httpx.Response(400, json={"detail": "Unexpected operation"})

    return httpx.MockTransport(handler)


def test_stateful_plan_discovers_id_then_blocks_access():
    result = execute_stateful_plan(
        make_plan(),
        principal_tokens={"Alice": "synthetic-token"},
        transport=make_transport(),
    )

    assert result.passed
    assert result.failure_count == 0
    assert result.steps[0].outcome == "ALLOWED"
    assert result.steps[1].outcome == "BLOCKED"


def test_stateful_plan_fails_when_foreign_child_is_exposed():
    result = execute_stateful_plan(
        make_plan(),
        principal_tokens={"Alice": "synthetic-token"},
        transport=make_transport(expose_child=True),
    )

    assert not result.passed
    assert result.steps[1].outcome == "EXPOSED_CONFIRMED"
    assert not result.steps[1].expectation_met


def test_missing_discovered_id_stops_followup_step():
    result = execute_stateful_plan(
        make_plan(),
        principal_tokens={"Alice": "synthetic-token"},
        transport=make_transport(empty_children=True),
    )

    assert not result.passed
    assert result.steps[1].outcome == "INCONCLUSIVE"
    assert "Variable resolution failed" in result.steps[1].detail


def test_future_or_self_reference_is_rejected():
    plan = StatefulPlan(
        plan_id="invalid-reference",
        steps=(
            StatefulStep(
                step_id="invalid",
                principal_id="Alice",
                query="query Read($id: ID!) { resource(id: $id) { id } }",
                variables={
                    "id": ResponseReference(
                        step_index=0,
                        json_path="data.resource.id",
                    )
                },
                expected_access="denied",
                response_path="data.resource",
                target_id_variable="id",
            ),
        ),
    )

    result = execute_stateful_plan(
        plan,
        principal_tokens={"Alice": "synthetic-token"},
        transport=make_transport(),
    )

    assert not result.passed
    assert result.steps[0].outcome == "INCONCLUSIVE"
    assert "earlier step" in result.steps[0].detail


def test_missing_token_is_inconclusive():
    result = execute_stateful_plan(
        make_plan(),
        principal_tokens={},
        transport=make_transport(),
    )

    assert not result.passed
    assert all(
        step.outcome == "INCONCLUSIVE"
        for step in result.steps
    )


def test_original_plan_variables_are_not_mutated():
    plan = make_plan()
    original = plan.steps[1].variables.copy()

    execute_stateful_plan(
        plan,
        principal_tokens={"Alice": "synthetic-token"},
        transport=make_transport(),
    )

    assert plan.steps[1].variables == original


def test_result_is_serializable():
    result = execute_stateful_plan(
        make_plan(),
        principal_tokens={"Alice": "synthetic-token"},
        transport=make_transport(),
    )

    payload = result.to_dict()

    assert payload["plan_id"] == "nested-bola-001"
    assert payload["step_count"] == 2
    assert "synthetic-token" not in json.dumps(payload)
