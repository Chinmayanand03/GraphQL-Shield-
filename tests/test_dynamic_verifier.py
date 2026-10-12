import httpx

from app.security.attack_generator import AttackCase
from app.security.dynamic_verifier import verify_attack_case


def make_case() -> AttackCase:
    return AttackCase(
        case_id="attack-test-001",
        principal_id="Alice",
        action="read",
        query="query GetResource($id: Int!) { resource(id: $id) { id name } }",
        variables={"id": 202},
        operation_name="GetResource",
        source_id="src-test",
        source_path="resource",
        source_kind="variable",
        target_type="Resource",
        target_id=202,
        target_owner_id="Bob",
        expected_authorized=False,
        reason="Synthetic cross-owner test",
    )


def make_transport(baseline_response, protected_response):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/graphql-insecure":
            return baseline_response

        if request.url.path == "/graphql":
            return protected_response

        return httpx.Response(404, json={"detail": "Not found"})

    return httpx.MockTransport(handler)


def test_confirmed_baseline_exposure_and_protected_block():
    transport = make_transport(
        httpx.Response(
            200,
            json={
                "data": {
                    "resource": {
                        "id": 202,
                        "name": "Bob's private record",
                    }
                }
            },
        ),
        httpx.Response(403, json={"detail": "Denied"}),
    )

    result = verify_attack_case(
        make_case(),
        token="synthetic-token",
        transport=transport,
    )

    assert result.baseline.outcome == "EXPOSED_CONFIRMED"
    assert result.protected.outcome == "BLOCKED"
    assert result.verdict == "PROTECTION_VERIFIED"


def test_protected_endpoint_exposing_target_is_failure():
    transport = make_transport(
        httpx.Response(
            200,
            json={"data": {"resource": {"id": 202, "name": "Private"}}},
        ),
        httpx.Response(
            200,
            json={"data": {"resource": {"id": 202, "name": "Private"}}},
        ),
    )

    result = verify_attack_case(
        make_case(),
        token="synthetic-token",
        transport=transport,
    )

    assert result.verdict == "PROTECTION_FAILED_CONFIRMED"


def test_data_without_visible_target_id_is_not_confirmed():
    transport = make_transport(
        httpx.Response(
            200,
            json={"data": {"resource": {"name": "Private"}}},
        ),
        httpx.Response(403, json={"detail": "Denied"}),
    )

    result = verify_attack_case(
        make_case(),
        token="synthetic-token",
        transport=transport,
    )

    assert result.baseline.outcome == "POSSIBLE_EXPOSURE"
    assert result.verdict == "BLOCKED_POSSIBLE_EXPOSURE_BASELINE"


def test_null_target_is_not_exposure():
    transport = make_transport(
        httpx.Response(200, json={"data": {"resource": None}}),
        httpx.Response(403, json={"detail": "Denied"}),
    )

    result = verify_attack_case(
        make_case(),
        token="synthetic-token",
        transport=transport,
    )

    assert result.baseline.outcome == "NOT_EXPOSED"
    assert result.verdict == "BASELINE_NOT_REPRODUCED"


def test_graphql_error_with_null_path_is_inconclusive():
    transport = make_transport(
        httpx.Response(
            200,
            json={
                "data": {"resource": None},
                "errors": [{"message": "Resolver failed"}],
            },
        ),
        httpx.Response(403, json={"detail": "Denied"}),
    )

    result = verify_attack_case(
        make_case(),
        token="synthetic-token",
        transport=transport,
    )

    assert result.baseline.outcome == "INCONCLUSIVE"
    assert result.baseline.graphql_errors == ("Resolver failed",)
    assert result.verdict == "INCONCLUSIVE"


def test_missing_response_path_is_inconclusive():
    transport = make_transport(
        httpx.Response(200, json={"data": {"other": None}}),
        httpx.Response(403, json={"detail": "Denied"}),
    )

    result = verify_attack_case(
        make_case(),
        token="synthetic-token",
        transport=transport,
    )

    assert result.baseline.outcome == "INCONCLUSIVE"
    assert not result.baseline.response_path_found


def test_result_can_be_serialized():
    transport = make_transport(
        httpx.Response(
            200,
            json={"data": {"resource": {"id": 202, "name": "Private"}}},
        ),
        httpx.Response(403, json={"detail": "Denied"}),
    )

    result = verify_attack_case(
        make_case(),
        token="synthetic-token",
        transport=transport,
    )

    payload = result.to_dict()

    assert payload["case_id"] == "attack-test-001"
    assert payload["verdict"] == "PROTECTION_VERIFIED"
    assert payload["baseline"]["target_id_observed"] is True


def test_invalid_timeout_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        verify_attack_case(
            make_case(),
            token="synthetic-token",
            timeout=0,
        )
