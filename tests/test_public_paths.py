from fastapi.testclient import TestClient

from app.core.paths import PROJECT_ROOT, public_message, public_path
from app.main import app

client = TestClient(app)


def test_project_paths_become_relative():
    assert public_path(PROJECT_ROOT / "app" / "models" / "x.json") == "app/models/x.json"


def test_outside_paths_show_only_the_file_name(tmp_path):
    assert public_path(tmp_path / "secret" / "model.json") == "model.json"


def test_error_messages_lose_the_project_location():
    message = f"No such file: '{PROJECT_ROOT / 'results' / 'model.json'}'"
    assert str(PROJECT_ROOT) not in public_message(message)
    assert "model.json" in public_message(message)


def test_model_status_endpoints_hide_the_server_layout():
    for url in ("/api/v1/research-evaluation", "/api/v1/security/blind-spot-model"):
        body = client.get(url).text
        assert str(PROJECT_ROOT) not in body and PROJECT_ROOT.as_posix() not in body
        assert str(PROJECT_ROOT).replace("\\", "\\\\") not in body  # JSON-escaped form
