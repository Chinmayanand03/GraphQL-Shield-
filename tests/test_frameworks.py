"""
Layer 2 inside real Graphene and Ariadne servers, with no Strawberry in the schema.

Graphene needs graphql-core below 3.3 and this repository's Strawberry needs 3.3, so
each test skips when its framework is not installed. requirements-frameworks.txt
is the environment that runs the Graphene tests.
"""
import base64
from types import SimpleNamespace

import pytest

from app.security.object_extractor import normalize_query
from app.security.runtime_object_guard import OwnershipMiddleware
from app.security.shield_config import ShieldConfig

NOTES = {1: {"id": 1, "body": "mine", "owner": 1}, 2: {"id": 2, "body": "secret", "owner": 2}}
WRITES = []


def request_for(user_id=1, role="user"):
    return SimpleNamespace(url=SimpleNamespace(path="/graphql"),
                           state=SimpleNamespace(current_user={"user_id": user_id, "role": role}))


def owner_of(_key, object_id):
    return NOTES.get(int(object_id), {}).get("owner")


def relay_decode(value):
    try:
        type_name, raw_id = base64.b64decode(str(value), validate=True).decode().split(":", 1)
    except Exception:
        return None, value
    return type_name, int(raw_id)


def relay_id(object_id):
    return base64.b64encode(f"NoteNode:{object_id}".encode()).decode()


@pytest.fixture()
def graphene_app():
    graphene = pytest.importorskip("graphene")
    from graphene import relay

    class NoteNode(graphene.ObjectType):
        class Meta:
            interfaces = (relay.Node,)

        body = graphene.String()

        @classmethod
        def get_node(cls, info, id):
            row = NOTES.get(int(id))
            return row and NoteNode(id=row["id"], body=row["body"])

    class Query(graphene.ObjectType):
        node = relay.Node.Field()
        note = graphene.Field(NoteNode, id=graphene.ID(required=True))
        notes = graphene.List(NoteNode)

        def resolve_note(self, info, id):
            row = NOTES.get(relay_decode(id)[1])
            return row and NoteNode(id=row["id"], body=row["body"])

        def resolve_notes(self, info):
            return [NoteNode(id=row["id"], body=row["body"]) for row in NOTES.values()]

    class EditNote(graphene.Mutation):
        class Arguments:
            id = graphene.ID(required=True)

        note = graphene.Field(NoteNode)

        def mutate(self, info, id):
            WRITES.append(id)
            return EditNote()

    class Mutation(graphene.ObjectType):
        edit_note = EditNote.Field()

    schema = graphene.Schema(query=Query, mutation=Mutation)
    config = ShieldConfig(schema=lambda: schema.graphql_schema, owned_types={"NoteNode": "NoteNode"},
                          owner_lookup=owner_of, decode_id=relay_decode,
                          mutation_targets={"editNote": ("id", "NoteNode")})

    def run(query):
        return schema.execute(query, context_value={"request": request_for()}, middleware=[OwnershipMiddleware(config)])

    return run, config


def test_graphene_relay_node_field_denies_a_foreign_object(graphene_app):
    run, _ = graphene_app
    assert run(f'{{ node(id: "{relay_id(2)}") {{ ... on NoteNode {{ body }} }} }}').data["node"] is None
    assert run(f'{{ node(id: "{relay_id(1)}") {{ ... on NoteNode {{ body }} }} }}').data["node"]["body"] == "mine"


def test_graphene_list_is_filtered(graphene_app):
    run, _ = graphene_app
    assert run("{ notes { body } }").data["notes"] == [{"body": "mine"}]


def test_graphene_foreign_mutation_never_runs(graphene_app):
    run, _ = graphene_app
    WRITES.clear()
    result = run(f'mutation {{ editNote(id: "{relay_id(2)}") {{ note {{ body }} }} }}')
    assert result.errors[0].extensions["code"] == "MUTATION_AUTHORIZATION_DENIED"
    assert WRITES == []


def test_layer1_reads_a_graphene_schema(graphene_app):
    _, config = graphene_app
    objects = normalize_query(f'{{ node(id: "{relay_id(2)}") {{ id }} }}', config=config)["objects"]
    assert objects == [{"type": "NoteNode", "id": 2, "path": "node"}]


@pytest.fixture()
def ariadne_app():
    ariadne = pytest.importorskip("ariadne")
    sdl = """
    type Note { id: ID! body: String! }
    type Query { note(id: ID!): Note notes: [Note!]! }
    type Mutation { editNote(id: ID!): Note }
    """
    query = ariadne.QueryType()
    mutation = ariadne.MutationType()
    query.set_field("note", lambda _, info, id: NOTES.get(int(id)))
    query.set_field("notes", lambda _, info: list(NOTES.values()))

    @mutation.field("editNote")
    def edit_note(_, info, id):
        WRITES.append(id)
        return NOTES.get(int(id))

    schema = ariadne.make_executable_schema(sdl, query, mutation)
    config = ShieldConfig(schema=lambda: schema, owned_types={"Note": "Note"}, owner_lookup=owner_of)

    def run(text):
        return ariadne.graphql_sync(schema, {"query": text}, context_value={"request": request_for()},
                                    middleware=[OwnershipMiddleware(config)])[1]

    return run


def test_ariadne_single_object_and_list(ariadne_app):
    assert ariadne_app('{ note(id: "2") { body } }')["data"]["note"] is None
    assert ariadne_app("{ notes { body } }")["data"]["notes"] == [{"body": "mine"}]


def test_ariadne_foreign_mutation_never_runs(ariadne_app):
    WRITES.clear()
    result = ariadne_app('mutation { editNote(id: "2") { body } }')
    assert result["errors"][0]["extensions"]["code"] == "MUTATION_AUTHORIZATION_DENIED"
    assert WRITES == []
