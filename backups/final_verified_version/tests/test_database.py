import os
import pytest
from app.database import get_db_connection
from app.seed import seed_database
from app.config import settings

@pytest.fixture(autouse=True)
def setup_test_db():
    # Use a test database
    original_url = settings.DATABASE_URL
    settings.DATABASE_URL = "sqlite:///./test_shield.db"
    
    # Run seed script
    seed_database()
    
    yield
    
    # Cleanup
    db_file = settings.DATABASE_URL.replace("sqlite:///", "")
    if os.path.exists(db_file):
        try:
            os.remove(db_file)
        except PermissionError:
            pass
    settings.DATABASE_URL = original_url

def test_database_creation():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row['name'] for row in cursor.fetchall()]
    
    assert 'users' in tables
    assert 'objects' in tables
    assert 'audit_logs' in tables
    
    conn.close()

def test_ownership_lookup():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check object 102 belongs to user 102
    cursor.execute("SELECT owner_id, name FROM objects WHERE id = ?", (102,))
    row = cursor.fetchone()
    assert row is not None
    assert row['owner_id'] == 102
    assert row['name'] == "Bob's Financial Record"
    
    # Check nested objects belong to Alice
    cursor.execute("SELECT owner_id, name FROM objects WHERE parent_id = ?", (201,))
    nested_objects = cursor.fetchall()
    assert len(nested_objects) == 2
    for obj in nested_objects:
        assert obj['owner_id'] == 101
        
    conn.close()
