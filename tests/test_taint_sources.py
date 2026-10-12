from app.security.taint_sources import track_sources


def test_variable_id_is_tracked():
    result = track_sources(
        "query GetUser($id: ID!) { user(id: $id) { username } }",
        {"id": "U101"},
    )

    assert result.valid
    assert len(result.sources) == 1
    assert result.sources[0].value == "U101"
    assert result.sources[0].source_kind == "variable"


def test_literal_id_is_tracked():
    result = track_sources(
        'query { resource(id: "R101") { name } }'
    )

    assert len(result.sources) == 1
    assert result.sources[0].value == "R101"
    assert result.sources[0].source_kind == "literal"


def test_nested_paths_are_tracked():
    query = """
    query GetNested($userId: ID!, $resourceId: ID!) {
        user(id: $userId) {
            resource(id: $resourceId) {
                name
            }
        }
    }
    """

    result = track_sources(
        query,
        {"userId": "U101", "resourceId": "R202"},
    )

    assert [
        (source.value, source.graphql_path)
        for source in result.sources
    ] == [
        ("U101", "user"),
        ("R202", "user.resource"),
    ]


def test_alias_is_used_in_response_path():
    result = track_sources(
        'query { selected: user(id: "U101") { username } }'
    )

    assert len(result.sources) == 1
    assert result.sources[0].field_name == "user"
    assert result.sources[0].graphql_path == "selected"


def test_fragment_source_is_tracked():
    query = """
    fragment ResourceFragment on User {
        resource(id: 303) {
            name
        }
    }

    query GetUser($id: ID!) {
        user(id: $id) {
            ...ResourceFragment
        }
    }
    """

    result = track_sources(query, {"id": "U101"})

    assert len(result.sources) == 2

    nested = next(
        source
        for source in result.sources
        if source.value == 303
    )

    assert nested.graphql_path == "user.resource"


def test_default_variable_is_tracked_when_missing():
    result = track_sources(
        'query Get($id: ID! = "U101") { user(id: $id) { id } }'
    )

    assert len(result.sources) == 1
    assert result.sources[0].value == "U101"
    assert result.sources[0].source_kind == "default"


def test_explicit_null_does_not_use_default():
    query = (
        'query Get($id: ID = "DEFAULT") '
        '{ user(id: $id) { id } }'
    )

    result = track_sources(query, {"id": None})

    assert result.sources == ()


def test_invalid_graphql_returns_warning():
    result = track_sources("query { user(id: ) { id } }")

    assert not result.valid
    assert result.sources == ()
    assert "invalid_graphql" in result.warnings


def test_non_id_argument_is_ignored_by_default():
    result = track_sources(
        'query { user(userId: "U101") { id } }'
    )

    assert result.sources == ()


def test_invalid_container_value_is_not_tracked():
    query = "query Get($id: ID) { user(id: $id) { id } }"

    result = track_sources(query, {"id": [101, 102]})

    assert result.sources == ()
