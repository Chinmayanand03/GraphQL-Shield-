from app.security.security_graph import add_sensitive_sinks
from app.security.taint_explanation import (
    explain_all_findings,
    explain_finding,
)
from app.security.taint_models import AuthorizationBoundary
from app.security.taint_propagation import propagate_taint
from app.security.taint_transfer import authorization_aware_transfer


def make_finding_result():
    result = propagate_taint(
        'query { resource(id: "R101") { name } }'
    )
    add_sensitive_sinks(result, ["resource.name"])

    boundary = AuthorizationBoundary(
        principal_id="Alice",
        action="read",
        object_type="Resource",
        object_id="R101",
        authorized=False,
        reason="Ownership mismatch",
        graphql_path="resource",
    )

    authorization_aware_transfer(
        result,
        principal_id="Alice",
        action="read",
        boundaries=[boundary],
    )

    return result


def test_explanation_contains_finding_evidence():
    result = make_finding_result()
    finding = result.findings[0]

    explanation = explain_finding(finding, result)

    assert explanation["finding_id"] == finding.finding_id
    assert explanation["status"] == "suspected"
    assert explanation["principal_id"] == "Alice"
    assert explanation["source_evidence"]
    assert explanation["authorization_evidence"]


def test_explanation_does_not_claim_suspected_is_confirmed():
    result = make_finding_result()

    explanation = explain_finding(result.findings[0], result)

    assert explanation["status"] == "suspected"
    assert "potentially unauthorized" in explanation["summary"]


def test_all_findings_can_be_explained():
    result = make_finding_result()

    explanations = explain_all_findings(result)

    assert len(explanations) == len(result.findings)
