import strawberry
from typing import Optional
from app.graphql.types import ResourceType
from app.database import get_db_connection

# Layer 2 ownership registry: for each root mutation (GraphQL field name), the
# argument that names the target object and that object's ownership type.
# Every mutation must be listed here; Layer 2 denies unlisted mutations.
MUTATION_TARGETS = {
    "updateResource": ("id", "Resource"),
    "deleteResource": ("id", "Resource"),
    "transferOwnership": ("id", "Resource"),
}


def _load_resource(conn, resource_id: int) -> Optional[ResourceType]:
    row = conn.execute("SELECT * FROM objects WHERE id = ?", (resource_id,)).fetchone()
    if row is None:
        return None
    return ResourceType(
        id=row["id"],
        name=row["name"],
        owner_id=row["owner_id"],
        object_type=row["object_type"],
        parent_id=row["parent_id"],
    )


@strawberry.type
class Mutation:
    """
    Write operations. Like the queries, these resolvers are deliberately written
    WITHOUT ownership checks (the BOLA baseline); GraphQL Shield must stop foreign
    writes before they execute:
      - Layer 1 blocks the request when it can see the target id in the query.
      - Layer 2 blocks the resolver call using the engine-coerced target argument
        listed in MUTATION_TARGETS.
    """

    @strawberry.mutation
    def update_resource(self, id: int, name: str) -> Optional[ResourceType]:
        conn = get_db_connection()
        try:
            conn.execute("UPDATE objects SET name = ? WHERE id = ?", (name, id))
            conn.commit()
            return _load_resource(conn, id)
        finally:
            conn.close()

    @strawberry.mutation
    def delete_resource(self, id: int) -> bool:
        conn = get_db_connection()
        try:
            # A deleted folder's children move to the top level, whoever owns them.
            # Refusing the delete instead would tell the caller that a hidden child
            # exists. The children keep their owner and content; only their place in
            # the deleted folder, which belonged to the folder's owner, goes away.
            conn.execute("UPDATE objects SET parent_id = NULL WHERE parent_id = ?", (id,))
            cursor = conn.execute("DELETE FROM objects WHERE id = ?", (id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception:
            conn.rollback()
            return False
        finally:
            conn.close()

    @strawberry.mutation
    def transfer_ownership(self, id: int, new_owner_id: int) -> Optional[ResourceType]:
        conn = get_db_connection()
        try:
            if conn.execute("SELECT 1 FROM users WHERE id = ?", (new_owner_id,)).fetchone() is None:
                raise ValueError(f"User {new_owner_id} does not exist.")
            conn.execute("UPDATE objects SET owner_id = ? WHERE id = ?", (new_owner_id, id))
            conn.commit()
            return _load_resource(conn, id)
        finally:
            conn.close()
