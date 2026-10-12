from app.security.taint_models import AuthorizationBoundary
from app.security.taint_propagation import propagate_taint
from app.security.taint_transfer import authorization_aware_transfer


def test_denied_direct_object_creates_suspected_finding():
    result = propagate_taint(
        'query { resource(id: "R101") { name } }'
    )

    boundary = AuthorizationBoundary(
        principal_id="Alice",
        action="read",
        object_type="Resource",
        object_id="R101",
        authorized=False,
        reason="Resource is owned by another user",
        graphql_path="resource",
    )

    authorization_aware_transfer(
        result,
        principal_id="Alice",
        action="read",
        boundaries=[boundary],
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.category == "direct_bola"
    )

    assert finding.status == "suspected"
    assert finding.target_id == "R101"


def test_denied_nested_object_creates_indirect_finding():
    result = propagate_taint(
        """
        query GetNested($userId: ID!, $resourceId: ID!) {
            user(id: $userId) {
                resource(id: $resourceId) {
                    name
                }
            }
        }
        """,
        {"userId": "U101", "resourceId": "R202"},
    )

    boundary = AuthorizationBoundary(
        principal_id="Alice",
        action="read",
        object_type="Resource",
        object_id="R202",
        authorized=False,
        reason="Nested resource access denied",
        graphql_path="user.resource",
    )

    authorization_aware_transfer(
        result,
        principal_id="Alice",
        action="read",
        boundaries=[boundary],
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.category == "indirect_bola"
    )

    assert finding.status == "suspected"
    assert finding.graphql_path == "user.resource"


def test_allowed_parent_does_not_authorize_denied_child():
    result = propagate_taint(
        """
        query GetNested($userId: ID!, $resourceId: ID!) {
            user(id: $userId) {
                resource(id: $resourceId) {
                    name
                }
            }
        }
        """,
        {"userId": "U101", "resourceId": "R202"},
    )

    boundaries = [
        AuthorizationBoundary(
            principal_id="Alice",
            action="read",
            object_type="User",
            object_id="U101",
            authorized=True,
            reason="User is accessible",
            graphql_path="user",
        ),
        AuthorizationBoundary(
            principal_id="Alice",
            action="read",
            object_type="Resource",
            object_id="R202",
            authorized=False,
            reason="Resource is not accessible",
            graphql_path="user.resource",
        ),
    ]

    authorization_aware_transfer(
        result,
        principal_id="Alice",
        action="read",
        boundaries=boundaries,
    )

    findings = [
        finding
        for finding in result.findings
        if finding.category == "indirect_bola"
    ]

    assert len(findings) == 1
    assert findings[0].target_id == "R202"


def test_unknown_authorization_is_inconclusive():
    result = propagate_taint(
        'query { resource(id: "R101") { name } }'
    )

    boundary = AuthorizationBoundary(
        principal_id="Alice",
        action="read",
        object_type="Resource",
        object_id="R101",
        authorized=None,
        reason="Policy could not be evaluated",
        graphql_path="resource",
    )

    authorization_aware_transfer(
        result,
        principal_id="Alice",
        action="read",
        boundaries=[boundary],
    )

    assert any(
        finding.category == "authorization_unknown"
        and finding.status == "inconclusive"
        for finding in result.findings
    )


def test_missing_sensitive_sink_boundary_is_inconclusive():
    result = propagate_taint(
        """
        query GetUser($id: ID!) {
            user(id: $id) {
                profile {
                    email
                }
            }
        }
        """,
        {"id": "U101"},
    )

    authorization_aware_transfer(
        result,
        principal_id="Alice",
        action="read",
        boundaries=[],
        sensitive_sink_paths=["user.profile.email"],
    )

    finding = next(
        finding
        for finding in result.findings
        if finding.category == "missing_authorization_boundary"
    )

    assert finding.status == "inconclusive"
    assert finding.graphql_path == "user.profile.email"


def test_allowed_boundary_does_not_create_bola_finding():
    result = propagate_taint(
        'query { resource(id: "R101") { name } }'
    )

    boundary = AuthorizationBoundary(
        principal_id="Alice",
        action="read",
        object_type="Resource",
        object_id="R101",
        authorized=True,
        reason="Owner access permitted",
        graphql_path="resource",
    )

    authorization_aware_transfer(
        result,
        principal_id="Alice",
        action="read",
        boundaries=[boundary],
    )

    assert not any(
        finding.category in {"direct_bola", "indirect_bola"}
        for finding in result.findings
    )


def test_boundary_is_represented_in_analysis_graph():
    result = propagate_taint(
        'query { resource(id: "R101") { name } }'
    )

    boundary = AuthorizationBoundary(
        principal_id="Alice",
        action="read",
        object_type="Resource",
        object_id="R101",
        authorized=False,
        reason="Access denied",
        graphql_path="resource",
    )

    authorization_aware_transfer(
        result,
        principal_id="Alice",
        action="read",
        boundaries=[boundary],
    )

    assert any(
        node.node_type == "authorization_boundary"
        for node in result.nodes
    )

    assert any(
        edge.edge_type == "authorization_boundary_failed"
        for edge in result.edges
    )
