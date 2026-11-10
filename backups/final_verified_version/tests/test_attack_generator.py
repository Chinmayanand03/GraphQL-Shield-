from app.security.attack_generator import (
    AttackTarget,
    generate_bola_attacks,
)


def test_generates_variable_substitution_attack():
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
                expected_authorized=False,
                owner_id="Bob",
                graphql_path="resource",
            )
        ],
    )

    assert len(result.cases) == 1

    case = result.cases[0]
    assert case.variables["id"] == 202
    assert case.expected_authorized is False
    assert case.operation_name == "GetResource"
    assert case.target_owner_id == "Bob"


def test_generates_literal_substitution_attack():
    query = 'query { resource(id: 101) { id name } }'

    result = generate_bola_attacks(
        query=query,
        variables={},
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=202,
                field_name="resource",
                expected_authorized=False,
            )
        ],
    )

    assert len(result.cases) == 1
    assert "resource(id: 202)" in result.cases[0].query


def test_skips_target_not_explicitly_unauthorized():
    result = generate_bola_attacks(
        query='query { resource(id: 101) { id } }',
        variables={},
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=202,
                field_name="resource",
                expected_authorized=True,
            )
        ],
    )

    assert result.cases == ()
    assert result.skipped


def test_skips_unchanged_target_id():
    result = generate_bola_attacks(
        query='query { resource(id: 101) { id } }',
        variables={},
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=101,
                field_name="resource",
                expected_authorized=False,
            )
        ],
    )

    assert result.cases == ()
    assert result.skipped


def test_does_not_mutate_original_variables():
    original = {"id": 101}

    generate_bola_attacks(
        query="query Get($id: Int!) { resource(id: $id) { id } }",
        variables=original,
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=202,
                field_name="resource",
                expected_authorized=False,
            )
        ],
    )

    assert original == {"id": 101}


def test_handles_literal_source_inside_fragment():
    query = """
    fragment Details on User {
        resource(id: 101) {
            name
        }
    }

    query GetUser($id: Int!) {
        user(id: $id) {
            ...Details
        }
    }
    """

    result = generate_bola_attacks(
        query=query,
        variables={"id": 10},
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=202,
                field_name="resource",
                expected_authorized=False,
                graphql_path="user.resource",
            )
        ],
    )

    assert len(result.cases) == 1
    assert "resource(id: 202)" in result.cases[0].query
    assert result.cases[0].source_path == "user.resource"


def test_invalid_query_returns_warning():
    result = generate_bola_attacks(
        query="query { resource(id: ) { id } }",
        variables={},
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=202,
                field_name="resource",
                expected_authorized=False,
            )
        ],
    )

    assert result.cases == ()
    assert "invalid_graphql" in result.warnings


def test_target_field_must_match_source_field():
    result = generate_bola_attacks(
        query='query { resource(id: 101) { id } }',
        variables={},
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="User",
                object_id=202,
                field_name="user",
                expected_authorized=False,
            )
        ],
    )

    assert result.cases == ()
    assert result.skipped


def test_attack_case_is_serializable():
    result = generate_bola_attacks(
        query='query { resource(id: 101) { id } }',
        variables={},
        principal_id="Alice",
        targets=[
            AttackTarget(
                object_type="Resource",
                object_id=202,
                field_name="resource",
                expected_authorized=False,
            )
        ],
    )

    payload = result.to_dict()

    assert payload["case_count"] == 1
    assert payload["cases"][0]["expected_authorized"] is False
    assert payload["cases"][0]["target_id"] == 202
