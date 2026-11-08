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


def _still_exists(node_id: str) -> bool:
    """Whether a test recorded by an earlier run still exists, so tests that were
    renamed or removed stop counting in the report."""
    path, _, name = node_id.partition("::")
    function = name.split("[")[0].split("::")[-1]
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", path), encoding="utf-8") as file:
            return f"def {function}(" in file.read()
    except OSError:
        return False


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
    previous = {node: outcome for node, outcome in previous.items() if _still_exists(node)}
    merged = {**previous, **_outcomes}

    def count(outcomes):
        totals = {status: sum(1 for s in outcomes.values() if s == status) for status in ("passed", "failed", "skipped")}
        return {**totals, "total": len(outcomes)}

    report = {
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "last_run": count(_outcomes),
        "all_tests": count(merged),
        "tests": merged,
    }
    try:
        os.makedirs(os.path.dirname(TEST_REPORT), exist_ok=True)
        with open(TEST_REPORT, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=1)
    except OSError:
        pass  # reporting must never fail the test run
