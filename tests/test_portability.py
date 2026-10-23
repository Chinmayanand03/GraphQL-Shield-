"""
Both layers protecting a second, unrelated GraphQL application: a schema-first
graphql-core server with dict resolvers, an orders/invoices domain, and Relay
global IDs. Nothing in it is Strawberry or this repository's demo schema; only a
ShieldConfig describes it.
"""
import base64
from types import SimpleNamespace

import pytest
from graphql import build_schema, graphql_sync

from app.security.object_extractor import normalize_query
from app.security.runtime_object_guard import OwnershipMiddleware
from app.security.shield_config import ShieldConfig

SDL = """
type Customer { id: ID! name: String! orders: [Order!]! }
type Order { id: ID! total: Float! customer: Customer! invoices: [Invoice!]! }
type Invoice { id: ID! amount: Float! }
type Query {
  order(id: ID!): Order
  invoice(id: ID!): Invoice
  me: Customer
}
type Mutation {
  cancelOrder(id: ID!): Order
  archive(target: ID!): Boolean
}
"""

CUSTOMERS = {1: {"id": 1, "name": "Asha"}, 2: {"id": 2, "name": "Ravi"}}
ORDERS = {10: {"id": 10, "total": 50.0, "owner": 1}, 20: {"id": 20, "total": 99.0, "owner": 2}}
INVOICES = {100: {"id": 100, "amount": 50.0, "owner": 1, "order": 10},
            200: {"id": 200, "amount": 99.0, "owner": 2, "order": 10}}  # foreign invoice on Asha's order
OWNERS = {"Customer": lambda i: i if i in CUSTOMERS else None,
          "Order": lambda i: ORDERS.get(i, {}).get("owner"),
          "Invoice": lambda i: INVOICES.get(i, {}).get("owner")}


def global_id(type_name, raw_id):
    return base64.b64encode(f"{type_name}:{raw_id}".encode()).decode()


def decode_global_id(value):
    """Relay global ID -> (ownership key, raw id); plain IDs pass through."""
    try:
        type_name, raw_id = base64.b64decode(str(value), validate=True).decode().split(":", 1)
        return type_name, int(raw_id)
    except Exception:
        return None, value


def raw(value):
    return decode_global_id(value)[1]


schema = build_schema(SDL)
schema.query_type.fields["order"].resolve = lambda _, info, id: ORDERS.get(raw(id))
schema.query_type.fields["invoice"].resolve = lambda _, info, id: INVOICES.get(raw(id))
schema.query_type.fields["me"].resolve = lambda _, info: CUSTOMERS[info.context["request"].state.current_user["user_id"]]
schema.get_type("Order").fields["invoices"].resolve = lambda order, info: [i for i in INVOICES.values() if i["order"] == order["id"]]
schema.get_type("Customer").fields["orders"].resolve = lambda c, info: [o for o in ORDERS.values() if o["owner"] == c["id"]]
WRITES = []
schema.mutation_type.fields["cancelOrder"].resolve = lambda _, info, id: WRITES.append(("cancel", raw(id))) or ORDERS.get(raw(id))
schema.mutation_type.fields["archive"].resolve = lambda _, info, target: WRITES.append(("archive", raw(target))) or True

CONFIG = ShieldConfig(
    schema=lambda: schema,
    owned_types={"Customer": "Customer", "Order": "Order", "Invoice": "Invoice"},
    owner_lookup=lambda key, object_id: OWNERS[key](object_id) if key in OWNERS else None,
    mutation_targets={"archive": ("target", "Order")},
    decode_id=decode_global_id,
)


def request(user_id=1, role="user"):
    return SimpleNamespace(url=SimpleNamespace(path="/graphql"),
                           state=SimpleNamespace(current_user={"user_id": user_id, "role": role}, layer1_checked=set()))


def run(query, user_id=1, role="user"):
    return graphql_sync(schema, query, context_value={"request": request(user_id, role)},
                        middleware=[OwnershipMiddleware(CONFIG)])


@pytest.fixture(autouse=True)
def clear_writes():
    WRITES.clear()


# ---------------------------------------------------------------- Layer 1 on a foreign schema

def test_layer1_reads_types_from_the_schema():
    objects = normalize_query(f'{{ order(id: "{global_id("Order", 20)}") {{ invoices {{ id }} }} invoice(id: 100) {{ id }} }}',
                              config=CONFIG)["objects"]
    assert {(o["type"], o["id"]) for o in objects} == {("Order", 20), ("Invoice", 100)}


def test_layer1_detects_global_id_type_confusion():
    # An Invoice ID passed where an Order is expected is checked as both types.
    objects = normalize_query(f'mutation {{ cancelOrder(id: "{global_id("Invoice", 200)}") {{ id }} }}', config=CONFIG)["objects"]
    assert {(o["type"], o["id"]) for o in objects} == {("Order", 200), ("Invoice", 200)}


def test_layer1_uses_mutation_registry_for_non_owned_return_types():
    objects = normalize_query(f'mutation {{ archive(target: "{global_id("Order", 20)}") }}', config=CONFIG)["objects"]
    assert {(o["type"], o["id"]) for o in objects} == {("Order", 20)}


# ---------------------------------------------------------------- Layer 2 as plain graphql-core middleware

def test_owner_reads_own_order():
    result = run(f'{{ order(id: "{global_id("Order", 10)}") {{ id total }} }}')
    assert result.errors is None and result.data["order"]["total"] == 50.0


def test_foreign_order_is_nulled():
    result = run(f'{{ order(id: "{global_id("Order", 20)}") {{ id total }} }}')
    assert result.data["order"] is None


def test_foreign_child_is_filtered_from_relationship():
    result = run(f'{{ order(id: "{global_id("Order", 10)}") {{ invoices {{ id amount }} }} }}')
    assert [i["id"] for i in result.data["order"]["invoices"]] == ["100"]


def test_admin_sees_everything():
    result = run(f'{{ order(id: "{global_id("Order", 10)}") {{ invoices {{ id }} }} }}', user_id=2, role="admin")
    assert len(result.data["order"]["invoices"]) == 2


def test_foreign_mutation_never_executes():
    result = run(f'mutation {{ cancelOrder(id: "{global_id("Order", 20)}") {{ id }} }}')
    assert result.errors and result.errors[0].extensions["code"] == "MUTATION_AUTHORIZATION_DENIED"
    assert WRITES == []


def test_registry_mutation_with_non_owned_return_type_is_guarded():
    result = run(f'mutation {{ archive(target: "{global_id("Order", 20)}") }}')
    assert result.errors and WRITES == []
    assert run(f'mutation {{ archive(target: "{global_id("Order", 10)}") }}').errors is None
    assert WRITES == [("archive", 10)]


def test_unprotected_path_is_not_guarded():
    insecure = request()
    insecure.url.path = "/graphql-insecure"
    result = graphql_sync(schema, f'{{ order(id: "{global_id("Order", 20)}") {{ id }} }}',
                          context_value={"request": insecure}, middleware=[OwnershipMiddleware(CONFIG)])
    assert result.data["order"]["id"] == "20"
