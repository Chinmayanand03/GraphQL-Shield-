import httpx

from app.benchmarks.integrated_verification import (
    build_attack_from_benchmark_case,
    verify_labelled_bola_cases,
)
from app.security.attack_generator import (
    AttackTarget,
    generate_bola_attacks,
)
from app.security.dynamic_verifier import verify_attack_case


def generate_test_case():
    query = """
    query GetResource($id: Int!) {
        resource(id: $id) {
            id
            name
        }
    }
    """

    generated = generate_bola_attacks(
        query=query,
        variables={"id": 101},
        principal_id="Alice",
        action="read",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=202,
                field_name="resource",
                expected_authorized=False,
                owner_id="Bob",
                graphql_path="resource",
                reason="Synthetic cross-owner access test",
            )
        ],
    )

    assert not generated.warnings, generated.warnings
    assert len(generated.cases) == 1

    return generated.cases[0]


def mock_transport(protected_exposes_target=False):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/graphql-insecure":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "resource": {
                            "id": 202,
                            "name": "Synthetic private record",
                        }
                    }
                },
            )

        if request.url.path == "/graphql":
            if protected_exposes_target:
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "resource": {
                                "id": 202,
                                "name": "Synthetic private record",
                            }
                        }
                    },
                )

            return httpx.Response(
                403,
                json={"detail": "Forbidden"},
            )

        return httpx.Response(404, json={"detail": "Not found"})

    return httpx.MockTransport(handler)


def test_attack_generation_and_dynamic_verification_integrate():
    case = generate_test_case()

    assert case.expected_authorized is False
    assert case.variables["id"] == 202
    assert case.source_path == "resource"

    result = verify_attack_case(
        case=case,
        token="synthetic-test-token",
        transport=mock_transport(),
    )

    assert result.baseline.outcome == "EXPOSED_CONFIRMED"
    assert result.protected.outcome == "BLOCKED"
    assert result.verdict == "PROTECTION_VERIFIED"


def test_integrated_verification_detects_protected_endpoint_leak():
    case = generate_test_case()

    result = verify_attack_case(
        case=case,
        token="synthetic-test-token",
        transport=mock_transport(
            protected_exposes_target=True,
        ),
    )

    assert result.baseline.outcome == "EXPOSED_CONFIRMED"
    assert result.protected.outcome == "EXPOSED_CONFIRMED"
    assert result.verdict == "PROTECTION_FAILED_CONFIRMED"


def test_authorized_target_is_not_generated_as_bola():
    query = """
    query GetResource($id: Int!) {
        resource(id: $id) {
            id
            name
        }
    }
    """

    result = generate_bola_attacks(
        query=query,
        variables={"id": 101},
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=202,
                field_name="resource",
                expected_authorized=True,
                owner_id="Alice",
                graphql_path="resource",
            )
        ],
    )

    assert result.cases == ()
    assert result.skipped


def test_failed_protected_request_is_not_misreported_as_success():
    case = generate_test_case()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/graphql-insecure":
            return httpx.Response(
                500,
                json={"detail": "Synthetic server error"},
            )

        if request.url.path == "/graphql":
            return httpx.Response(
                403,
                json={"detail": "Forbidden"},
            )

        return httpx.Response(404)

    result = verify_attack_case(
        case=case,
        token="synthetic-test-token",
        transport=httpx.MockTransport(handler),
    )

    assert result.baseline.outcome == "INCONCLUSIVE"
    assert result.protected.outcome == "BLOCKED"
    assert result.verdict == "INCONCLUSIVE"


def make_case():
    return {
        "case_id": "case-test-001",
        "scenario": "direct_bola",
        "principal_id": 101,
        "role": "user",
        "query": (
            "query BenchmarkDirect($id: Int!) { "
            "resource(id: $id) { id name } }"
        ),
        "variables": {"id": 101},
        "operation_name": "BenchmarkDirect",
        "target_type": "Resource",
        "target_id": 102,
        "target_owner_id": 102,
        "graphql_path": "resource",
        "sensitive_sink_path": "resource.name",
        "is_bola": True,
        "expected_authorized": False,
    }


def test_builds_attack_from_known_synthetic_case():
    attack, reason = build_attack_from_benchmark_case(make_case())

    assert reason is None
    assert attack is not None
    assert attack.expected_authorized is False
    assert attack.variables["id"] == 102


def test_replay_reports_actual_baseline_and_protected_outcomes(tmp_path):
    class FakeClient:
        def request(self, method, url, headers=None, content=None):
            if url == "/graphql-insecure":
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "resource": {
                                "id": 102,
                                "name": "Bob synthetic record",
                            }
                        }
                    },
                )

            if url == "/graphql":
                return httpx.Response(
                    403,
                    json={"detail": "Forbidden"},
                )

            return httpx.Response(404, json={"detail": "Not found"})

    result = verify_labelled_bola_cases(
        test_client=FakeClient(),
        cases=[make_case()],
        tokens={101: "synthetic-test-token"},
        output_dir=tmp_path,
    )

    assert result["attack_cases_generated_and_executed"] == 1
    assert result["baseline_confirmed_exposures"] == 1
    assert result["protected_blocks"] == 1
    assert result["verdict_counts"]["PROTECTION_VERIFIED"] == 1
    assert (tmp_path / "integrated_dynamic_verification.json").exists()
    assert (tmp_path / "integrated_dynamic_verification_raw.csv").exists()


def test_skips_legitimate_cases(tmp_path):
    case = make_case()
    case["is_bola"] = False
    case["expected_authorized"] = True

    result = verify_labelled_bola_cases(
        test_client=object(),
        cases=[case],
        tokens={101: "synthetic-test-token"},
        output_dir=tmp_path,
    )

    assert result["labelled_bola_cases"] == 0
    assert result["attack_cases_generated_and_executed"] == 0
    assert result["http_requests_for_replays"] == 0
