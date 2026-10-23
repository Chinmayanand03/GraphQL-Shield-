import os
import sys

# Ensure the root directory is in the path to import app correctly when run directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database import close_pooled_connections, get_db_connection, init_db
from app.config import settings
from app.core.passwords import hash_password

# The test suite reseeds before every test, so seeded demo accounts use fewer
# PBKDF2 iterations; the stored hash records its own iteration count.
SEED_ITERATIONS = 10_000


def demo_password(username: str) -> str:
    return f"{username}123"

def seed_database():
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    # Start fresh for development, including WAL side files from a previous database.
    close_pooled_connections(db_file)
    for path in (db_file, f"{db_file}-wal", f"{db_file}-shm"):
        if os.path.exists(path):
            os.remove(path)
        
    init_db()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Seed Users. Every demo password follows one format: <username>123.
    users = [
        (101, "balanilavan", "user", "B.V. Balanilavan"),
        (102, "kapilesh", "user", "Kapilesh N"),
        (103, "sakthivel", "user", "Sakthivel B"),
        (104, "chinmayanand", "admin", "Admin Demo Account"),
    ]
    cursor.executemany(
        "INSERT INTO users (id, username, password_hash, role, display_name) VALUES (?, ?, ?, ?, ?)",
        [
            (user_id, username, hash_password(demo_password(username), iterations=SEED_ITERATIONS), role, display_name)
            for user_id, username, role, display_name in users
        ]
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

SHARED_FOLDER_OBJECT = (204, "document", 102, "Kapilesh's Shared Draft", 201)


def add_shared_folder_scenario():
    """Relationship-BOLA demo data: Kapilesh's document filed inside Balanilavan's folder.

    Owning the folder must NOT grant access to this child. Kept out of the default
    seed so existing tests keep their exact fixtures.
    """
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO objects (id, object_type, owner_id, name, parent_id) VALUES (?, ?, ?, ?, ?)",
            SHARED_FOLDER_OBJECT,
        )
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    seed_database()
    if "--with-shared-folder" in sys.argv:
        add_shared_folder_scenario()
        print("Added shared-folder scenario (object 204 owned by Kapilesh inside folder 201).")
    print("Database successfully seeded.")
