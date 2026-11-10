import strawberry
from typing import Optional
from app.graphql.types import HealthCheckType, UserType, ResourceType
from app.database import get_db_connection

@strawberry.type
class Query:
    @strawberry.field
    def health(self) -> HealthCheckType:
        return HealthCheckType(status="ok", message="GraphQL API is healthy")
        
    @strawberry.field
    def user(self, id: int) -> Optional[UserType]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return UserType(id=row["id"], username=row["username"], role=row["role"])
        return None

    @strawberry.field
    def resource(self, id: int) -> Optional[ResourceType]:
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
