"""
Account takeover is prevented, not only recorded: password guessing is locked out,
sign-in replies and timing do not reveal which usernames exist, tokens can be ended
before they expire, the role is read from the database, and new passwords must be
strong.
"""
import statistics
import time

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core import accounts
from app.core.passwords import hash_password
from app.core.security import create_access_token
from app.database import get_db_connection
from app.main import app

client = TestClient(app)


def login(username, password):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def protected(token):
    return client.get("/api/v1/protected", headers=bearer(token))


@pytest.fixture
def account():
    """A throwaway account, so changing its password or role cannot affect other tests."""
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = 990")
    conn.execute("INSERT INTO users (id, username, password_hash, role, display_name) VALUES (990, 'tempuser', ?, 'user', 'Temp')",
                 (hash_password("tempuser123"),))
    conn.commit()
    conn.close()
    yield {"id": 990, "username": "tempuser", "password": "tempuser123"}
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = 990")
    conn.commit()
    conn.close()


# ------------------------------------------------------------------- password guessing

def test_five_wrong_passwords_lock_the_account_even_for_the_right_password(account):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        assert login(account["username"], "wrong-guess").status_code == 401
    locked = login(account["username"], account["password"])
    assert locked.status_code == 429
    assert int(locked.headers["Retry-After"]) > 0


def test_unknown_usernames_are_locked_the_same_way():
    """Otherwise the lockout itself would reveal which usernames exist."""
    for _ in range(settings.LOGIN_MAX_FAILURES):
        response = login("nobody-here", "guess")
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid username or password"}
    assert login("nobody-here", "guess").status_code == 429


def test_wrong_password_and_unknown_user_get_the_same_reply(account):
    assert login(account["username"], "wrong").json() == login("no-such-user", "wrong").json()


def test_a_successful_sign_in_resets_the_count(account):
    for _ in range(settings.LOGIN_MAX_FAILURES - 1):
        login(account["username"], "wrong")
    assert login(account["username"], account["password"]).status_code == 200
    for _ in range(settings.LOGIN_MAX_FAILURES - 1):
        login(account["username"], "wrong")
    assert login(account["username"], account["password"]).status_code == 200


def test_many_failures_from_one_address_block_it_for_every_username(account):
    for attempt in range(settings.LOGIN_IP_MAX_FAILURES):
        login(f"spray-{attempt}", "guess")  # one guess per username, below the per-user limit
    assert login(account["username"], account["password"]).status_code == 429


def test_the_lock_expires(account, monkeypatch):
    for _ in range(settings.LOGIN_MAX_FAILURES):
        login(account["username"], "wrong")
    assert login(account["username"], account["password"]).status_code == 429
    later = time.time() + settings.LOGIN_LOCK_SECONDS + 1
    monkeypatch.setattr(accounts.time, "time", lambda: later)
    assert login(account["username"], account["password"]).status_code == 200


def test_sign_in_takes_as_long_for_an_unknown_username(account, monkeypatch):
    """Timing must not reveal which usernames exist."""
    monkeypatch.setattr(settings, "LOGIN_MAX_FAILURES", 1000)
    monkeypatch.setattr(settings, "LOGIN_IP_MAX_FAILURES", 1000)

    def timed(username):
        start = time.perf_counter()
        login(username, "definitely-wrong")
        return time.perf_counter() - start

    known = statistics.median(timed(account["username"]) for _ in range(7))
    unknown = statistics.median(timed("not-a-user") for _ in range(7))
    assert 0.6 < unknown / known < 1.6


# ---------------------------------------------------------------------- sessions

def test_logout_ends_the_token_before_it_expires(account):
    token = login(account["username"], account["password"]).json()["access_token"]
    assert protected(token).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=bearer(token)).status_code == 200
    assert protected(token).status_code == 401


def test_logout_everywhere_ends_every_session(account):
    phone = login(account["username"], account["password"]).json()["access_token"]
    laptop = login(account["username"], account["password"]).json()["access_token"]
    client.post("/api/v1/auth/logout-all", headers=bearer(laptop))
    assert protected(phone).status_code == 401
    assert protected(laptop).status_code == 401
    assert protected(login(account["username"], account["password"]).json()["access_token"]).status_code == 200


def test_a_token_cannot_grant_a_role_the_account_does_not_have():
    token = create_access_token(user_id=101, role="admin")  # 101 is a normal user
    assert client.get("/api/v1/audit-logs", headers=bearer(token)).status_code == 403


def test_a_removed_role_stops_working_at_once(account):
    conn = get_db_connection()
    conn.execute("UPDATE users SET role = 'admin' WHERE id = 990")
    conn.commit()
    token = login(account["username"], account["password"]).json()["access_token"]
    assert client.get("/api/v1/audit-logs", headers=bearer(token)).status_code == 200
    conn.execute("UPDATE users SET role = 'user' WHERE id = 990")
    conn.commit()
    conn.close()
    assert client.get("/api/v1/audit-logs", headers=bearer(token)).status_code == 403


def test_a_deleted_account_cannot_use_its_token(account):
    token = login(account["username"], account["password"]).json()["access_token"]
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = 990")
    conn.commit()
    conn.close()
    assert protected(token).status_code == 401


def test_a_forged_token_is_rejected():
    import base64
    import json

    head, payload, signature = create_access_token(user_id=101, role="user").split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["user_id"] = 102
    forged = ".".join([head, base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("="), signature])
    assert protected(forged).status_code == 401


# --------------------------------------------------------------------- passwords

def change(token, current, new):
    return client.post("/api/v1/auth/change-password", headers=bearer(token),
                       json={"current_password": current, "new_password": new})


def test_changing_the_password_needs_the_current_one(account):
    token = login(account["username"], account["password"]).json()["access_token"]
    assert change(token, "not-my-password", "A-much-better-pass-42").status_code == 401


def test_wrong_current_passwords_are_locked_out_too(account):
    """A stolen session must not become a way to guess the password."""
    token = login(account["username"], account["password"]).json()["access_token"]
    for _ in range(settings.LOGIN_MAX_FAILURES):
        change(token, "guess", "A-much-better-pass-42")
    assert change(token, account["password"], "A-much-better-pass-42").status_code == 429


@pytest.mark.parametrize("weak", ["short1!", "tempuser-and-more", "password123", "aaaaaaaaaaaaaaaa"])
def test_weak_new_passwords_are_refused(account, weak):
    token = login(account["username"], account["password"]).json()["access_token"]
    response = change(token, account["password"], weak)
    assert response.status_code == 400
    assert response.json()["detail"]["problems"]


def test_a_password_change_ends_other_sessions_and_the_new_password_works(account):
    other_device = login(account["username"], account["password"]).json()["access_token"]
    this_device = login(account["username"], account["password"]).json()["access_token"]
    response = change(this_device, account["password"], "Correct-Horse-Battery-9")
    assert response.status_code == 200
    assert protected(other_device).status_code == 401
    assert protected(this_device).status_code == 401
    assert protected(response.json()["access_token"]).status_code == 200
    assert login(account["username"], account["password"]).status_code == 401
    assert login(account["username"], "Correct-Horse-Battery-9").status_code == 200


def test_production_refuses_to_start_with_demo_passwords(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    with pytest.raises(RuntimeError, match="demo passwords"):
        accounts.check_production_accounts()


def test_development_allows_demo_passwords():
    accounts.check_production_accounts()
