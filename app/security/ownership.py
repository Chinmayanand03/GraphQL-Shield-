from app.database import get_db_connection

def get_object_owners(object_type: str, object_ids: list[int]) -> dict[int, int]:
    """Owners of many objects in one query. An object with no row is simply absent."""
    table, owner = ("users", "id") if object_type.lower() == "user" else ("objects", "owner_id")
    placeholders = ", ".join("?" for _ in object_ids)
    conn = get_db_connection()
    try:
        rows = conn.execute(f"SELECT id, {owner} FROM {table} WHERE id IN ({placeholders})", list(object_ids)).fetchall()
    finally:
        conn.close()
    return {row[0]: row[1] for row in rows}


def get_object_owner(object_type: str, object_id: int) -> int | None:
    """
    Looks up the owner of a given object from the database based on its type.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if object_type.lower() == "user":
            # A user "owns" their own user record
            cursor.execute("SELECT id FROM users WHERE id = ?", (object_id,))
            row = cursor.fetchone()
            if row:
                return row["id"]
            return None
            
        else:
            # Default to resources/objects table
            cursor.execute("SELECT owner_id FROM objects WHERE id = ?", (object_id,))
            row = cursor.fetchone()
            if row:
                return row["owner_id"]
            return None
    finally:
        conn.close()
