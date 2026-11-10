from app.security.taint_propagation import propagate_taint


def test_parent_id_taint_propagates_to_nested_fields():
    query = """
    query GetUser($id: ID!) {
        user(id: $id) {
            id
            profile {
                email
            }
        }
    }
    """

    result = propagate_taint(query, {"id": "U101"})

    assert len(result.sources) == 1

    nodes = {
        node.graphql_path: node
        for node in result.nodes
        if node.node_type == "graphql_field"
    }

    source_id = result.sources[0].source_id

    assert source_id in nodes["user"].taint_source_ids
    assert source_id in nodes["user.profile"].taint_source_ids
    assert source_id in nodes["user.profile.email"].taint_source_ids


def test_nested_id_adds_taint_without_losing_parent_context():
    query = """
    query GetNested($userId: ID!, $resourceId: ID!) {
        user(id: $userId) {
            resource(id: $resourceId) {
                name
            }
        }
    }
    """

    result = propagate_taint(
        query,
        {"userId": "U101", "resourceId": "R202"},
    )

    nodes = {
        node.graphql_path: node
        for node in result.nodes
        if node.node_type == "graphql_field"
    }

    user_source = next(
        source.source_id
        for source in result.sources
        if source.value == "U101"
    )
    resource_source = next(
        source.source_id
        for source in result.sources
        if source.value == "R202"
    )

    assert user_source in nodes["user.resource"].taint_source_ids
    assert resource_source in nodes["user.resource"].taint_source_ids
    assert user_source in nodes["user.resource.name"].taint_source_ids
    assert resource_source in nodes["user.resource.name"].taint_source_ids


def test_sibling_branches_keep_contexts_separate():
    query = """
    query GetUser($userId: ID!, $resourceId: ID!) {
        user(id: $userId) {
            primary: resource(id: $resourceId) {
                name
            }
            profile {
                email
            }
        }
    }
    """

    result = propagate_taint(
        query,
        {"userId": "U101", "resourceId": "R202"},
    )

    nodes = {
        node.graphql_path: node
        for node in result.nodes
        if node.node_type == "graphql_field"
    }

    user_source = next(
        source.source_id
        for source in result.sources
        if source.value == "U101"
    )
    resource_source = next(
        source.source_id
        for source in result.sources
        if source.value == "R202"
    )

    assert user_source in nodes["user.profile"].taint_source_ids
    assert resource_source not in nodes["user.profile"].taint_source_ids
    assert resource_source in nodes[
        "user.primary"
    ].taint_source_ids


def test_aliases_have_distinct_contexts():
    query = """
    query {
        first: user(id: "U101") {
            id
        }
        second: user(id: "U101") {
            id
        }
    }
    """

    result = propagate_taint(query)

    nodes = [
        node
        for node in result.nodes
        if node.node_type == "graphql_field"
        and node.label == "user"
    ]

    assert len(nodes) == 2
    assert {node.graphql_path for node in nodes} == {
        "first",
        "second",
    }
    assert len({node.context_key for node in nodes}) == 2


def test_fragment_propagation_preserves_nested_context():
    query = """
    fragment UserDetails on User {
        resource(id: "R202") {
            name
        }
    }

    query GetUser($id: ID!) {
        user(id: $id) {
            ...UserDetails
        }
    }
    """

    result = propagate_taint(query, {"id": "U101"})

    nodes = {
        node.graphql_path: node
        for node in result.nodes
        if node.node_type == "graphql_field"
    }

    assert "user.resource" in nodes

    source_ids = set(nodes["user.resource"].taint_source_ids)
    source_values = {
        source.value: source.source_id
        for source in result.sources
    }

    assert source_values["U101"] in source_ids
    assert source_values["R202"] in source_ids


def test_propagation_edges_are_recorded():
    query = """
    query GetUser($id: ID!) {
        user(id: $id) {
            profile {
                email
            }
        }
    }
    """

    result = propagate_taint(query, {"id": "U101"})

    propagation_edges = [
        edge
        for edge in result.edges
        if edge.edge_type == "taint_propagation"
    ]

    assert any(
        edge.field_name == "profile"
        for edge in propagation_edges
    )
    assert any(
        edge.field_name == "email"
        for edge in propagation_edges
    )


def test_invalid_graphql_returns_warning():
    result = propagate_taint("query { user(id: ) { id } }")

    assert result.nodes == []
    assert result.edges == []
    assert "invalid_graphql" in result.warnings


def test_separate_operations_do_not_share_taint():
    query = """
    query First($id: ID!) {
        user(id: $id) {
            username
        }
    }

    query Second {
        resource(id: "R202") {
            name
        }
    }
    """

    result = propagate_taint(query, {"id": "U101"})

    nodes = {
        node.graphql_path: node
        for node in result.nodes
        if node.node_type == "graphql_field"
    }

    user_source = next(
        source.source_id
        for source in result.sources
        if source.value == "U101"
    )
    resource_source = next(
        source.source_id
        for source in result.sources
        if source.value == "R202"
    )

    assert user_source in nodes["user"].taint_source_ids
    assert resource_source not in nodes["user"].taint_source_ids
    assert resource_source in nodes["resource"].taint_source_ids
    assert user_source not in nodes["resource"].taint_source_ids
