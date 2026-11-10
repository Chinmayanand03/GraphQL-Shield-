import strawberry
from typing import List, Optional
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
    def children(self) -> List["ResourceType"]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM objects WHERE parent_id = ?", (self.id,))
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
