import os
import tempfile

# The test suite exercises the insecure benchmark baseline and the layer toggle,
# both of which are off by default. Set before app.config is first imported.
os.environ.setdefault("ENABLE_INSECURE_BASELINE", "true")
os.environ.setdefault("ENABLE_LAYER_TOGGLE", "true")

# Tests never touch the developer's shield.db: every test that does not choose
# its own database uses a freshly seeded one in a temporary folder.
_TEST_DB = os.path.join(tempfile.mkdtemp(prefix="shield-tests-"), "shield.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"


def pytest_sessionstart(session):
    from app.clinic.data import init_clinic
    from app.seed import seed_database

    seed_database()
    init_clinic()


def pytest_sessionfinish(session, exitstatus):
    from app.database import close_pooled_connections

    close_pooled_connections()
