import strawberry
from typing import List, Optional
from strawberry.types import Info
from app.database import get_db_connection
from app.security.layers import is_enabled

@strawberry.type
class HealthCheckType:
    status: str
    message: str

@strawberry.type
class ResourceType:
    id: int
    name: str
    owner_id: int
    object_type: str
    parent_id: Optional[int]

    @strawberry.field
    def children(self, info: Info) -> List["ResourceType"]:
        """Return child objects of this folder.

        Ownership is NOT checked here. On the protected endpoint the Layer 2 runtime
        object guard filters every returned child independently: owning a folder does
        not grant access to a child owned by another subject (administrators may read
        all children). The insecure benchmark endpoint keeps the unfiltered behavior.
        """
        conn = get_db_connection()
        try:
            rows = conn.execute("SELECT * FROM objects WHERE parent_id = ?", (self.id,)).fetchall()
        finally:
            conn.close()

        return [
            ResourceType(
                id=row["id"],
                name=row["name"],
                owner_id=row["owner_id"],
                object_type=row["object_type"],
                parent_id=row["parent_id"],
            )
            for row in rows
        ]

    @strawberry.field
    def children_count(self, info: Info) -> int:
        """
        Count children visible to the current requester on the
        protected endpoint.

        The insecure endpoint deliberately counts all children
        so it remains useful as a vulnerable benchmark baseline.
        """
        conn = get_db_connection()
        try:
            rows = conn.execute(
                "SELECT owner_id FROM objects WHERE parent_id = ?",
                (self.id,),
            ).fetchall()
        finally:
            conn.close()

        context = getattr(info, "context", None)

        if isinstance(context, dict):
            request = context.get("request")
        else:
            request = getattr(context, "request", None)

        path = str(
            getattr(getattr(request, "url", None), "path", "")
        ).rstrip("/")

        # Preserve intentionally vulnerable baseline behaviour (also when Layer 2 is
        # switched off for the layer ablation).
        if path == "/graphql-insecure" or not is_enabled("layer2"):
            return len(rows)

        # On the protected endpoint, fail closed if context is absent.
        current_user = getattr(
            getattr(request, "state", None),
            "current_user",
            None,
        )

        if not isinstance(current_user, dict):
            return 0

        role = str(current_user.get("role", "user")).upper()

        # Administrators may count all children under the current policy.
        if role == "ADMIN":
            return len(rows)

        requester_id = current_user.get("user_id")
        if requester_id is None:
            return 0

        # Count only children the requester owns.
        return sum(
            1
            for row in rows
            if str(row["owner_id"]) == str(requester_id)
        )


@strawberry.type
class UserType:
    id: int
    username: str
    role: str
    
    @strawberry.field
    def resources(self) -> List[ResourceType]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM objects WHERE owner_id = ?", (self.id,))
        rows = cursor.fetchall()
        conn.close()
        return [
            ResourceType(
                id=row["id"], 
                name=row["name"], 
                owner_id=row["owner_id"], 
                object_type=row["object_type"], 
                parent_id=row["parent_id"]
            ) for row in rows
        ]

    @strawberry.field
    def resource(self, id: int) -> Optional[ResourceType]:
        """
        Nested relationship to fetch a specific resource by ID under a user.
        Used to test nested BOLA attacks.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM objects WHERE id = ?", (id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return ResourceType(
                id=row["id"], 
                name=row["name"], 
                owner_id=row["owner_id"], 
                object_type=row["object_type"], 
                parent_id=row["parent_id"]
            )
        return None
