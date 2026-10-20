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
        (101, "balanilavan", "hash_balanilavan123", "user", "B.V. Balanilavan"),
        (102, "kapilesh", "hash_kapilesh123", "user", "Kapilesh N"),
        (103, "sakthivel", "hash_sakthivel123", "user", "Sakthivel B"),
        (104, "chinmayanand", "hash_chinmayanand123", "admin", "Admin Demo Account"),
    ]
    cursor.executemany(
        "INSERT INTO users (id, username, password_hash, role, display_name) VALUES (?, ?, ?, ?, ?)",
        users
    )
    
    # Seed Objects (with some nested relationships)
    objects = [
        # (id, object_type, owner_id, name, parent_id)
        (101, "document", 101, "Balanilavan's Secret Note", None),
        (102, "document", 102, "Kapilesh's Financial Record", None),
        (103, "document", 103, "Sakthivel B's Research Note", None),
        (104, "document", 104, "Chinmayanand's Admin Log", None),
        (201, "folder", 101, "Balanilavan's Projects", None),
        (202, "document", 101, "Project Alpha Plan", 201),
        (203, "document", 101, "Project Beta Plan", 201),
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
