import os
import sys

# Ensure the root directory is in the path to import app correctly when run directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database import get_db_connection, init_db
from app.config import settings

def seed_database():
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    # Start fresh for development
    if os.path.exists(db_file):
        os.remove(db_file)
        
    init_db()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Seed Users
    users = [
        (101, 'alice', 'hash_alice123', 'user'),
        (102, 'bob', 'hash_bob123', 'user'),
        (103, 'charlie', 'hash_charlie123', 'admin')
    ]
    cursor.executemany(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
        users
    )
    
    # Seed Objects (with some nested relationships)
    objects = [
        # (id, object_type, owner_id, name, parent_id)
        (101, 'document', 101, "Alice's Secret Note", None),
        (102, 'document', 102, "Bob's Financial Record", None),
        (103, 'document', 103, "Charlie's Admin Log", None),
        # Nested relationship: Alice has a folder that contains another document
        (201, 'folder', 101, "Alice's Projects", None),
        (202, 'document', 101, "Project Alpha Plan", 201),
        (203, 'document', 101, "Project Beta Plan", 201)
    ]
    cursor.executemany(
        "INSERT INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, ?, ?, ?, ?)",
        objects
    )
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    seed_database()
    print("Database successfully seeded.")
