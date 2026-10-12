import strawberry
from typing import List, Optional
from strawberry.types import Info
from app.database import get_db_connection

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
        """Return child objects, applying per-child ownership on the protected API.

        The insecure benchmark endpoint intentionally retains the unfiltered behavior.
        The protected endpoint filters each child independently: owning a folder does
        not grant access to a child owned by another subject. Administrators may read
        all children, consistent with the gateway's admin policy.
        """
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM objects WHERE parent_id = ?", (self.id,))
            rows = cursor.fetchall()
        finally:
            conn.close()

        context = getattr(info, "context", None)
        request = None
        if isinstance(context, dict):
            request = context.get("request")
        elif context is not None:
            request = getattr(context, "request", None)
            if request is None:
                getter = getattr(context, "get", None)
                if callable(getter):
                    try:
                        request = getter("request")
                    except Exception:
                        request = None

        # /graphql-insecure is the intentionally vulnerable benchmark baseline.
        # Only filter the protected route; never use the client-supplied parent
        # object's ownership as a substitute for checking each returned child.
        path = str(getattr(getattr(request, "url", None), "path", "")).rstrip("/")
        if path == "/graphql":
            current_user = getattr(getattr(request, "state", None), "current_user", None)
            if not isinstance(current_user, dict):
                # Fail closed if the protected route somehow lacks authenticated context.
                return []

            role = str(current_user.get("role", "user")).upper()
            if role != "ADMIN":
                requester_id = current_user.get("user_id")
                if requester_id is None:
                    return []
                rows = [row for row in rows if str(row["owner_id"]) == str(requester_id)]

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
