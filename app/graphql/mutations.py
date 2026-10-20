import strawberry
from typing import Optional
from app.graphql.types import ResourceType
from app.database import get_db_connection


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
      - Layer 2 blocks the resolver call using the engine-coerced `id` argument.
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
            cursor = conn.execute("DELETE FROM objects WHERE id = ?", (id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception:
            # e.g. a folder that still has children (foreign key constraint)
            return False
        finally:
            conn.close()

    @strawberry.mutation
    def transfer_ownership(self, id: int, new_owner_id: int) -> Optional[ResourceType]:
        conn = get_db_connection()
        try:
            conn.execute("UPDATE objects SET owner_id = ? WHERE id = ?", (new_owner_id, id))
            conn.commit()
            return _load_resource(conn, id)
        finally:
            conn.close()
