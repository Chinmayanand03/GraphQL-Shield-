import json
import os
import tempfile
from datetime import datetime, timezone

# The test suite exercises the insecure benchmark baseline and the layer toggle,
# both of which are off by default. Set before app.config is first imported.
os.environ.setdefault("ENABLE_INSECURE_BASELINE", "true")
os.environ.setdefault("ENABLE_LAYER_TOGGLE", "true")

# Tests never touch the developer's shield.db: every test that does not choose
# its own database uses a freshly seeded one in a temporary folder.
_TEST_DB = os.path.join(tempfile.mkdtemp(prefix="shield-tests-"), "shield.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"

# Where the dashboard reads the latest real test results from (git-ignored).
TEST_REPORT = os.path.join(os.path.dirname(__file__), "..", "results", "verification", "latest_test_run.json")
_outcomes: dict[str, str] = {}


def pytest_sessionstart(session):
    from app.clinic.data import init_clinic
    from app.seed import seed_database

    seed_database()
    init_clinic()


def pytest_runtest_logreport(report):
    # A test fails if any phase fails; it passes only when its call phase passes.
    if report.failed:
        _outcomes[report.nodeid] = "failed"
    elif report.when == "call" and report.passed:
        _outcomes.setdefault(report.nodeid, "passed")
    elif report.skipped:
        _outcomes.setdefault(report.nodeid, "skipped")


def pytest_sessionfinish(session, exitstatus):
    from app.database import close_pooled_connections

    close_pooled_connections()
    _write_test_report()


def _write_test_report() -> None:
    """Save this run's results, merged with earlier runs' per-test outcomes, so a
    partial run updates only the tests it ran."""
    if not _outcomes:
        return
    try:
        with open(TEST_REPORT, encoding="utf-8") as file:
            previous = json.load(file).get("tests", {})
    except (OSError, ValueError):
        previous = {}
    counts = {status: sum(1 for s in _outcomes.values() if s == status) for status in ("passed", "failed", "skipped")}
    report = {
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "last_run": {**counts, "total": len(_outcomes)},
        "tests": {**previous, **_outcomes},
    }
    try:
        os.makedirs(os.path.dirname(TEST_REPORT), exist_ok=True)
        with open(TEST_REPORT, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=1)
    except OSError:
        pass  # reporting must never fail the test run
