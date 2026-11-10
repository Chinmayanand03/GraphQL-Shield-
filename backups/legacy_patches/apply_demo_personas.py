from __future__ import annotations

import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path.cwd()
MAIN_PATH = PROJECT_ROOT / "app" / "main.py"
DASHBOARD_PATH = PROJECT_ROOT / "app" / "static" / "dashboard.html"
DATABASE_MODULE_PATH = PROJECT_ROOT / "app" / "database.py"

# The old seeded usernames remain accepted as backwards-compatible login aliases.
# Existing password hashes are preserved. Sakthivel's password is development-only.
PERSONAS = [
    {
        "username": "chinmay",
        "legacy_username": None,
        "display_name": "Admin Demo Account",
        "id": 104,
        "role": "admin",
        "new_account": False,
    },
    {
        "username": "bala",
        "legacy_username": None,
        "display_name": "B.V. Balanilavan",
        "id": 101,
        "role": "user",
        "new_account": False,
    },
    {
        "username": "kapilesh",
        "legacy_username": None,
        "display_name": "Kapilesh N",
        "id": 102,
        "role": "user",
        "new_account": False,
    },
    {
        "username": "sakthivel",
        "legacy_username": None,
        "display_name": "Sakthivel B",
        "id": 103,
        "role": "user",
        "new_account": True,
    },
]

LOGIN_ROUTE = '''LOGIN_USERNAME_ALIASES = {
    "bala": "balanilavan",
    "balanilavan": "bala",
    "kapil": "kapilesh",
    "kapilesh": "kapil",
    "chinmay": "chinmayanand",
    "chinmayanand": "chinmay",
    "sakthi": "sakthivel",
    "sakthivel": "sakthi",
}


@app.post("/api/v1/auth/login")
def login(request: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    """Development login endpoint with friendly and legacy username aliases."""
    expected_hash = f"hash_{request.password}"
    requested_username = request.username.strip().lower()
    candidates = [requested_username]
    alias = LOGIN_USERNAME_ALIASES.get(requested_username)
    if alias and alias not in candidates:
        candidates.append(alias)

    cursor = db.cursor()
    user = None
    for candidate in candidates:
        cursor.execute(
            "SELECT id, role FROM users WHERE username = ? AND password_hash = ?",
            (candidate, expected_hash),
        )
        user = cursor.fetchone()
        if user:
            break

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(user_id=user["id"], role=user["role"])
    return {"access_token": access_token, "token_type": "bearer"}


'''

DASHBOARD_STATS_FUNCTION = '''@app.get("/api/v1/dashboard-stats")
def get_dashboard_stats(db: sqlite3.Connection = Depends(get_db)):
    """Return dashboard metrics, recent audit events, and safe demo-user metadata."""
    cursor = db.cursor()

    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_requests = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE decision = 'ALLOW'")
    allowed = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE decision = 'DENY'")
    blocked = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*) FROM audit_logs
        WHERE reason IN ('OWNERSHIP_MISMATCH', 'NESTED_AUTHORIZATION_VIOLATION')
        """
    )
    bola_attempts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE risk_level = 'HIGH'")
    high_risk = cursor.fetchone()[0]

    user_columns = {
        row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()
    }
    if "display_name" in user_columns:
        cursor.execute(
            """
            SELECT a.*,
                   u.username AS username,
                   u.display_name AS display_name,
                   COALESCE(
                       NULLIF(u.display_name, ''),
                       CASE u.username
                           WHEN 'chinmay' THEN 'Admin Demo Account'
                                                      WHEN 'bala' THEN 'B.V. Balanilavan'
                                                      WHEN 'kapilesh' THEN 'Kapilesh N'
                                                      WHEN 'sakthivel' THEN 'Sakthivel B'
                           ELSE u.username
                       END,
                       CAST(a.user_id AS TEXT)
                   ) AS actor_name,
                   COALESCE(u.role, a.role) AS actor_role
            FROM audit_logs AS a
            LEFT JOIN users AS u ON u.id = a.user_id
            ORDER BY a.timestamp DESC
            LIMIT 15
            """
        )
    else:
        cursor.execute(
            """
            SELECT a.*,
                   u.username AS username,
                   CASE u.username
                       WHEN 'chinmay' THEN 'Admin Demo Account'
                                              WHEN 'bala' THEN 'B.V. Balanilavan'
                                              WHEN 'kapilesh' THEN 'Kapilesh N'
                                              WHEN 'sakthivel' THEN 'Sakthivel B'
                       ELSE u.username
                   END AS display_name,
                   COALESCE(
                       CASE u.username
                           WHEN 'chinmay' THEN 'Admin Demo Account'
                                                      WHEN 'bala' THEN 'B.V. Balanilavan'
                                                      WHEN 'kapilesh' THEN 'Kapilesh N'
                                                      WHEN 'sakthivel' THEN 'Sakthivel B'
                           ELSE u.username
                       END,
                       CAST(a.user_id AS TEXT)
                   ) AS actor_name,
                   COALESCE(u.role, a.role) AS actor_role
            FROM audit_logs AS a
            LEFT JOIN users AS u ON u.id = a.user_id
            ORDER BY a.timestamp DESC
            LIMIT 15
            """
        )
    recent_logs = [dict(row) for row in cursor.fetchall()]

    demo_users = []
    for persona in (
        {"username": "chinmay", "legacy_username": None, "display_name": "Admin Demo Account", "role": "ADMIN"},
        {"username": "bala", "legacy_username": None, "display_name": "B.V. Balanilavan", "role": "USER"},
        {"username": "kapilesh", "legacy_username": None, "display_name": "Kapilesh N", "role": "USER"},
        {"username": "sakthivel", "legacy_username": None, "display_name": "Sakthivel B", "role": "USER"},
    ):
        candidates = [persona["username"]]
        if persona["legacy_username"]:
            candidates.append(persona["legacy_username"])
        placeholders = ", ".join("?" for _ in candidates)
        if "display_name" in user_columns:
            cursor.execute(
                f"SELECT id, username, role, display_name FROM users WHERE username IN ({placeholders}) ORDER BY CASE username WHEN ? THEN 0 ELSE 1 END LIMIT 1",
                (*candidates, persona["username"]),
            )
        else:
            cursor.execute(
                f"SELECT id, username, role FROM users WHERE username IN ({placeholders}) ORDER BY CASE username WHEN ? THEN 0 ELSE 1 END LIMIT 1",
                (*candidates, persona["username"]),
            )
        row = cursor.fetchone()
        if row is None:
            continue
        item = dict(row)
        # Expose the friendly login alias on the dashboard even when a test DB
        # was freshly seeded with legacy usernames for backwards compatibility.
        item["username"] = persona["username"]
        item["display_name"] = persona["display_name"]
        item["role"] = persona["role"]
        demo_users.append(item)

    return {
        "stats": {
            "total": total_requests,
            "allowed": allowed,
            "blocked": blocked,
            "bola": bola_attempts,
            "high_risk": high_risk,
        },
        "recent_logs": recent_logs,
        "demo_users": demo_users,
    }
'''

PERSONA_SECTION = '''      <section class="panel section-gap" id="demo-personas">
        <div class="panel-head">
          <div><div class="panel-title">Demo users and roles</div><div class="panel-subtitle">Named local test accounts. Select an account to fill the test-console username; enter its demo password yourself.</div></div>
          <span class="range-chip">LOCAL DEMO ACCOUNTS</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Display name</th><th>User ID</th><th>Role</th><th>Login username</th><th>Action</th></tr></thead>
            <tbody id="demoUsersBody"><tr><td class="empty" colspan="5">Loading demo accounts…</td></tr></tbody>
          </table>
        </div>
        <div class="insight"><div class="insight-icon">ⓘ</div><div><strong>Demo identity note</strong><p>These are local demonstration accounts. Existing passwords for the original accounts are preserved. Sakthivel's development-only password is sakthivel123; do not reuse it outside local testing.</p></div></div>
      </section>

'''

RENDER_DEMO_USERS_FUNCTION = '''      function renderDemoUsers(users) {
        const body = $('demoUsersBody');
        if (!body) return;
        body.replaceChildren();
        if (!Array.isArray(users) || users.length === 0) {
          const tr = document.createElement('tr');
          const td = document.createElement('td');
          td.colSpan = 5;
          td.className = 'empty';
          td.textContent = 'No demo accounts were returned by the API.';
          tr.appendChild(td);
          body.appendChild(tr);
          return;
        }
        for (const user of users) {
          const tr = document.createElement('tr');
          const nameCell = document.createElement('td');
          const nameMain = document.createElement('div');
          nameMain.className = 'primary-cell';
          nameMain.textContent = user.display_name || user.username || 'Unknown user';
          const nameSub = document.createElement('div');
          nameSub.className = 'secondary-cell';
          nameSub.textContent = 'Demo account';
          nameCell.append(nameMain, nameSub);

          const idCell = document.createElement('td');
          idCell.textContent = user.id == null ? '—' : String(user.id);

          const roleCell = document.createElement('td');
          const rolePill = document.createElement('span');
          const role = String(user.role || 'USER').toUpperCase();
          rolePill.className = 'role-pill ' + (role === 'ADMIN' ? 'admin' : 'user');
          rolePill.textContent = role;
          roleCell.appendChild(rolePill);

          const usernameCell = document.createElement('td');
          usernameCell.textContent = user.username || '—';

          const actionCell = document.createElement('td');
          const selectButton = document.createElement('button');
          selectButton.type = 'button';
          selectButton.className = 'btn';
          selectButton.textContent = 'Use account';
          selectButton.dataset.demoUsername = user.username || '';
          selectButton.disabled = !user.username;
          actionCell.appendChild(selectButton);

          tr.append(nameCell, idCell, roleCell, usernameCell, actionCell);
          body.appendChild(tr);
        }
      }

'''


def fail(message: str) -> None:
    raise RuntimeError(message)


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def get_sqlite_path() -> Path:
    try:
        from app.config import settings
    except Exception as exc:
        fail(f"Could not load app.config settings: {exc}")
    database_url = str(settings.DATABASE_URL)
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        fail(f"This helper supports SQLite only; DATABASE_URL is {database_url!r}.")
    raw = database_url[len(prefix):]
    path = Path(raw)
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def find_persona_rows(conn: sqlite3.Connection) -> dict[str, sqlite3.Row | None]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT id, username, password_hash, role FROM users").fetchall()
    by_username: dict[str, sqlite3.Row] = {str(row["username"]): row for row in rows}
    selected: dict[str, sqlite3.Row | None] = {}
    for persona in PERSONAS:
        candidates = [persona["username"]]
        legacy = persona["legacy_username"]
        if legacy:
            candidates.append(legacy)
        matches = [by_username[name] for name in candidates if name in by_username]
        if len(matches) > 1:
            fail(
                f"Both {candidates[0]!r} and {candidates[-1]!r} exist as separate rows. "
                "Resolve this duplicate manually; no migration was performed."
            )
        selected[persona["username"]] = matches[0] if matches else None

    for persona in PERSONAS[:3]:
        if selected[persona["username"]] is None:
            fail(
                f"Could not find the existing account for {persona['display_name']!r}. "
                "Expected one of its current or legacy usernames. No migration was performed."
            )

    selected_ids = {
        int(row["id"]) for row in selected.values() if row is not None
    }
    target_ids = {int(persona["id"]) for persona in PERSONAS}
    occupied_unknown = [
        (int(row["id"]), str(row["username"]))
        for row in rows
        if int(row["id"]) in target_ids and int(row["id"]) not in selected_ids
    ]
    if occupied_unknown:
        details = ", ".join(f"ID {uid} ({name})" for uid, name in occupied_unknown)
        fail(
            f"A non-persona account occupies a target ID: {details}. "
            "No migration was performed."
        )
    return selected


def preflight() -> tuple[Path, str, str]:
    required_paths = (MAIN_PATH, DASHBOARD_PATH, DATABASE_MODULE_PATH)
    for path in required_paths:
        if not path.exists():
            fail(f"Required project file not found: {path}. Run from the project root.")
    main_text = MAIN_PATH.read_text(encoding="utf-8-sig")
    html_text = DASHBOARD_PATH.read_text(encoding="utf-8-sig")
    required_main_markers = [
        '@app.post("/api/v1/auth/login")',
        '@app.get("/api/v1/dashboard-stats")',
        '@app.get("/dashboard"',
    ]
    if any(marker not in main_text for marker in required_main_markers):
        fail("Could not safely locate required login/dashboard routes in app/main.py. No files were changed.")
    required_html_markers = [
        'id="test-console"',
        'function renderStats(stats)',
        'async function refresh(',
        'id="logsBody"',
    ]
    if any(marker not in html_text for marker in required_html_markers):
        # Older dashboard.html (from the first dashboard patch) did not yet
        # contain the browser-based GraphQL test console. Prefer the known
        # compatible bundled console as the starting point in that case.
        bundled_dashboard = PROJECT_ROOT / "payload" / "app" / "static" / "dashboard.html"
        if not bundled_dashboard.exists():
            fail(
                "The current dashboard lacks the GraphQL test-console markers, and the bundled "
                "compatible dashboard is missing. Extract the complete patch ZIP into the project root. "
                "No files were changed."
            )
        candidate_html = bundled_dashboard.read_text(encoding="utf-8-sig")
        if any(marker not in candidate_html for marker in required_html_markers):
            fail("Neither the current nor bundled dashboard has the expected markers. No files were changed.")
        html_text = candidate_html
        print("Using the bundled compatible dashboard because the current file has no GraphQL test console.")

    db_path = get_sqlite_path()
    if not db_path.exists():
        fail(f"Configured database does not exist: {db_path}. Initialize/seed the local database first.")
    with sqlite3.connect(str(db_path)) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing_tables = {"users", "audit_logs"} - tables
        if missing_tables:
            fail("Configured database is missing required table(s): " + ", ".join(sorted(missing_tables)))
        find_persona_rows(conn)
    return db_path, main_text, html_text


def backup_everything(db_path: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = PROJECT_ROOT / "backups" / f"demo_personas_pre_patch_{stamp}"
    backup_dir.mkdir(parents=True, exist_ok=False)
    shutil.copy2(MAIN_PATH, backup_dir / "main.py")
    shutil.copy2(DASHBOARD_PATH, backup_dir / "dashboard.html")
    shutil.copy2(DATABASE_MODULE_PATH, backup_dir / "database.py")
    seed_path = PROJECT_ROOT / "app" / "seed.py"
    if seed_path.exists():
        shutil.copy2(seed_path, backup_dir / "seed.py")
    src = sqlite3.connect(str(db_path))
    dst = sqlite3.connect(str(backup_dir / "database_backup.sqlite"))
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    return backup_dir


def referring_user_columns(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    references: list[tuple[str, str]] = []
    tables = [
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ]
    for table in tables:
        if table == "users":
            continue
        for fk in conn.execute(f"PRAGMA foreign_key_list({quote_identifier(table)})"):
            # PRAGMA foreign_key_list: id, seq, table, from, to, ...
            if str(fk[2]).lower() == "users" and str(fk[4]).lower() == "id":
                references.append((table, str(fk[3])))
    # Some older local schemas missed FK declarations on audit fields. Include
    # these known conventional columns only if they actually exist.
    for table, column in (("audit_logs", "user_id"), ("objects", "owner_id")):
        if table in tables:
            columns = {row[1] for row in conn.execute(f"PRAGMA table_info({quote_identifier(table)})")}
            if column in columns and (table, column) not in references:
                references.append((table, column))
    return references


def migrate_database(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    # Must be disabled before opening the migration transaction so IDs can be
    # moved temporarily while every known user FK is remapped within this transaction.
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        conn.execute("BEGIN IMMEDIATE")
        user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        if "display_name" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT")

        selected = find_persona_rows(conn)
        all_user_ids = [int(row[0]) for row in conn.execute("SELECT id FROM users")]
        max_id = max(all_user_ids + [int(p["id"]) for p in PERSONAS] + [0])
        references = referring_user_columns(conn)

        mapping: list[dict[str, Any]] = []
        occupied_by_persona_ids = set()
        for index, persona in enumerate(PERSONAS, start=1):
            row = selected[persona["username"]]
            if row is None:
                continue
            old_id = int(row["id"])
            if old_id in occupied_by_persona_ids:
                fail("The same database row was mapped to two personas; no migration was performed.")
            occupied_by_persona_ids.add(old_id)
            mapping.append({
                "persona": persona,
                "old_id": old_id,
                "temp_id": max_id + 1000 + index,
                "old_username": str(row["username"]),
            })

        selected_ids = {entry["old_id"] for entry in mapping}
        target_ids = {int(p["id"]) for p in PERSONAS}
        unknown_conflicts = [
            (int(row[0]), str(row[1]))
            for row in conn.execute("SELECT id, username FROM users")
            if int(row[0]) in target_ids and int(row[0]) not in selected_ids
        ]
        if unknown_conflicts:
            details = ", ".join(f"ID {uid} ({name})" for uid, name in unknown_conflicts)
            fail(f"A non-persona account occupies a required ID: {details}.")

        # First move all references and selected users to unique temporary IDs,
        # preventing collisions when swapping user 103 and user 104.
        for entry in mapping:
            for table, column in references:
                conn.execute(
                    f"UPDATE {quote_identifier(table)} SET {quote_identifier(column)} = ? WHERE {quote_identifier(column)} = ?",
                    (entry["temp_id"], entry["old_id"]),
                )
            conn.execute(
                "UPDATE users SET id = ?, username = ? WHERE id = ?",
                (entry["temp_id"], f"__persona_migration_{entry['temp_id']}__", entry["old_id"]),
            )

        # Move accounts into the requested IDs and set their desired usernames,
        # display names, and roles. Original password hashes remain unchanged.
        for entry in mapping:
            persona = entry["persona"]
            conn.execute(
                "UPDATE users SET id = ?, username = ?, display_name = ?, role = ? WHERE id = ?",
                (
                    int(persona["id"]),
                    persona["username"],
                    persona["display_name"],
                    persona["role"],
                    entry["temp_id"],
                ),
            )
            for table, column in references:
                conn.execute(
                    f"UPDATE {quote_identifier(table)} SET {quote_identifier(column)} = ? WHERE {quote_identifier(column)} = ?",
                    (int(persona["id"]), entry["temp_id"]),
                )

        # Add Sakthivel only when this account does not already exist. A known
        # prior installation may have created him at a different ID; that row
        # was remapped above, preserving its password hash.
        if selected["sakthivel"] is None:
            conn.execute(
                "INSERT INTO users (id, username, password_hash, role, display_name) VALUES (?, ?, ?, ?, ?)",
                (103, "sakthivel", "hash_sakthivel123", "user", "Sakthivel B"),
            )

        # Keep current persona fields canonical if re-running the installer.
        for persona in PERSONAS:
            conn.execute(
                "UPDATE users SET display_name = ?, role = ? WHERE id = ? AND username = ?",
                (persona["display_name"], persona["role"], int(persona["id"]), persona["username"]),
            )

        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            sample = "; ".join(str(tuple(row)) for row in violations[:5])
            fail(f"Foreign-key validation failed; transaction will roll back. Examples: {sample}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.close()


def replace_between(text: str, start_marker: str, end_marker: str, replacement: str, label: str) -> str:
    start = text.find(start_marker)
    if start < 0:
        fail(f"Could not find the beginning of {label}. No code file has been written.")
    end = text.find(end_marker, start + len(start_marker))
    if end < 0:
        fail(f"Could not find the end of {label}. No code file has been written.")
    return text[:start] + replacement + text[end:]


def patch_main(main_text: str) -> str:
    patched = replace_between(
        main_text,
        '@app.post("/api/v1/auth/login")',
        '@app.get("/api/v1/protected")',
        LOGIN_ROUTE,
        "login route",
    )
    patched = replace_between(
        patched,
        '@app.get("/api/v1/dashboard-stats")',
        '@app.get("/dashboard"',
        DASHBOARD_STATS_FUNCTION + "\n\n",
        "dashboard statistics route",
    )
    return patched


def patch_dashboard(html_text: str) -> str:
    if 'id="demo-personas"' not in html_text:
        nav_marker = '<a href="#audit-logs"><span class="nav-icon">≡</span>Audit events</a>'
        if nav_marker not in html_text:
            fail("Could not find dashboard navigation insertion point. No code file has been written.")
        html_text = html_text.replace(
            nav_marker,
            '<a href="#demo-personas"><span class="nav-icon">♟</span>Demo users</a>\n          ' + nav_marker,
            1,
        )
        marker = '      <section class="panel section-gap" id="test-console">'
        if marker not in html_text:
            fail("Could not find GraphQL test-console insertion point. No code file has been written.")
        html_text = html_text.replace(marker, PERSONA_SECTION + marker, 1)

    if ".role-pill" not in html_text:
        css_marker = "    .status-inline { font-size:11px; color:var(--muted); }"
        css_rules = """    .role-pill { display:inline-flex; border-radius:999px; padding:4px 9px; font-size:10px; letter-spacing:.5px; font-weight:850; border:1px solid var(--line); }
    .role-pill.admin { color:var(--amber); background:rgba(255,198,109,.10); border-color:rgba(255,198,109,.28); }
    .role-pill.user { color:var(--green); background:rgba(67,214,160,.08); border-color:rgba(67,214,160,.22); }
"""
        if css_marker not in html_text:
            fail("Could not find dashboard CSS insertion point. No code file has been written.")
        html_text = html_text.replace(css_marker, css_rules + css_marker, 1)

    old_fields_variants = [
        "const actorFields = ['actor_name', 'username', 'user_name', 'principal_id', 'user_id', 'subject_id', 'actor'];",
        "const actorFields = ['username', 'user_name', 'principal_id', 'user_id', 'subject_id', 'actor'];",
    ]
    new_fields = "const actorFields = ['actor_name', 'display_name', 'username', 'user_name', 'principal_id', 'user_id', 'subject_id', 'actor'];"
    for old_fields in old_fields_variants:
        if old_fields in html_text:
            html_text = html_text.replace(old_fields, new_fields, 1)
            break

    if "function renderDemoUsers(users)" not in html_text:
        render_marker = "      function renderStats(stats) {"
        if render_marker not in html_text:
            fail("Could not find dashboard render-function insertion point. No code file has been written.")
        html_text = html_text.replace(render_marker, RENDER_DEMO_USERS_FUNCTION + render_marker, 1)

    old_assign = "          state.stats = payload.stats; state.logs = payload.recent_logs;\n          renderStats(state.stats); applyFilters();"
    new_assign = "          state.stats = payload.stats; state.logs = payload.recent_logs;\n          renderDemoUsers(payload.demo_users || []);\n          renderStats(state.stats); applyFilters();"
    if new_assign not in html_text:
        if old_assign not in html_text:
            fail("Could not find dashboard refresh assignment point. No code file has been written.")
        html_text = html_text.replace(old_assign, new_assign, 1)

    listener_marker = "        $('runTestButton').addEventListener('click', runSelectedTest);"
    listener = """        $('demoUsersBody').addEventListener('click', (event) => {
          const button = event.target.closest('button[data-demo-username]');
          if (!button || !button.dataset.demoUsername) return;
          $('testUsername').value = button.dataset.demoUsername;
          $('testPassword').focus();
          $('test-console').scrollIntoView({behavior:'smooth', block:'start'});
          showToast('Account selected. Enter its demo password to run a test.');
        });
"""
    if "button[data-demo-username]" not in html_text:
        if listener_marker not in html_text:
            fail("Could not find dashboard event-listener insertion point. No code file has been written.")
        html_text = html_text.replace(listener_marker, listener + listener_marker, 1)
    return html_text


def main() -> int:
    try:
        db_path, main_text, html_text = preflight()
        patched_main = patch_main(main_text)
        patched_html = patch_dashboard(html_text)
        backup_dir = backup_everything(db_path)
        migrate_database(db_path)
        MAIN_PATH.write_text(patched_main, encoding="utf-8")
        DASHBOARD_PATH.write_text(patched_html, encoding="utf-8")

        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, username, display_name, role FROM users WHERE username IN (?, ?, ?, ?) ORDER BY id",
                ("bala", "kapilesh", "sakthivel", "chinmay"),
            ).fetchall()
        print("Demo personas configured successfully:")
        for row in rows:
            print(
                f"  ID {row['id']}: {row['display_name']} | "
                f"{str(row['role']).upper()} | login={row['username']}"
            )
        print(f"\nBackup saved to: {backup_dir}")
        print("New login usernames are chinmay, bala, kapilesh, and sakthivel.")
        print("Active demo accounts: balanilavan, kapilesh, sakthivel, chinmayanand.")
        print("Existing passwords for the original three accounts are preserved.")
        print("Sakthivel's local demo password is sakthivel123; change it before any non-local use.")
        print("Do not expose the demo dashboard or test accounts to the public internet.")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("Review the error and backup before retrying. No successful migration is claimed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
