"""
database.py  —  SQLite setup and baseline management
Changes from original:
  • avg_rate_per_minute column added to user_baselines (fixes Rule 2 unit bug)
  • role column added to sessions and user_baselines
  • intent_clamped, intent_confidence, honeypot_hit columns added to sessions
  • update_baseline() accepts calls_per_minute and role parameters
  • Migration block handles existing DBs safely
  • USERS dict provides demo authentication without a separate auth service
"""
import sqlite3
import os

DB_PATH = "data/sessions.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs("data", exist_ok=True)
    conn   = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id           TEXT    NOT NULL,
            role              TEXT    DEFAULT 'junior_analyst',
            declared_intent   TEXT    NOT NULL,
            intent_category   TEXT    NOT NULL,
            original_intent   TEXT,
            intent_clamped    INTEGER DEFAULT 0,
            intent_confidence REAL    DEFAULT 1.0,
            honeypot_hit      INTEGER DEFAULT 0,
            api_calls         TEXT    NOT NULL,
            hour_of_access    INTEGER,
            deviation_score   REAL,
            decision          TEXT,
            explanation       TEXT,
            risk_level        TEXT,
            timestamp         DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_baselines (
            user_id               TEXT    PRIMARY KEY,
            role                  TEXT    DEFAULT 'junior_analyst',
            avg_calls_per_session REAL    DEFAULT 20,
            avg_hour              REAL    DEFAULT 10,
            avg_rate_per_minute   REAL    DEFAULT 15,
            session_count         INTEGER DEFAULT 0,
            updated_at            DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Safe migration for existing databases — each ALTER is caught if already done
    migrations = [
        "ALTER TABLE user_baselines ADD COLUMN avg_rate_per_minute REAL DEFAULT 15",
        "ALTER TABLE user_baselines ADD COLUMN role TEXT DEFAULT 'junior_analyst'",
        "ALTER TABLE sessions ADD COLUMN role TEXT DEFAULT 'junior_analyst'",
        "ALTER TABLE sessions ADD COLUMN original_intent TEXT",
        "ALTER TABLE sessions ADD COLUMN intent_clamped INTEGER DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN intent_confidence REAL DEFAULT 1.0",
        "ALTER TABLE sessions ADD COLUMN honeypot_hit INTEGER DEFAULT 0",
    ]
    for sql in migrations:
        try:
            cursor.execute(sql)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()


def get_baseline(user_id: str) -> dict:
    conn = get_connection()
    row  = conn.execute(
        "SELECT * FROM user_baselines WHERE user_id = ?", (user_id,)
    ).fetchone()
    conn.close()

    if row:
        return {
            "avg_calls_per_session": row["avg_calls_per_session"],
            "avg_hour":              row["avg_hour"],
            "avg_rate_per_minute":   row["avg_rate_per_minute"],
            "session_count":         row["session_count"],
            "role":                  row["role"],
        }
    return {
        "avg_calls_per_session": 20,
        "avg_hour":              10,
        "avg_rate_per_minute":   15,
        "session_count":          0,
        "role":                  "junior_analyst",
    }


def update_baseline(user_id: str, total_calls: int,
                    hour: int, calls_per_minute: float = 15.0,
                    role: str = "junior_analyst"):
    """
    Updates the rolling average baseline for a user after each session.
    Incremental average formula: new_avg = old + (new - old) / count
    Now also tracks avg_rate_per_minute so Rule 2 has a correct comparator.
    """
    conn     = get_connection()
    existing = conn.execute(
        "SELECT * FROM user_baselines WHERE user_id = ?", (user_id,)
    ).fetchone()

    if existing:
        n             = existing["session_count"] + 1
        old_calls     = existing["avg_calls_per_session"]
        old_hour      = existing["avg_hour"]
        old_rate      = existing["avg_rate_per_minute"]
        new_avg_calls = old_calls + (total_calls      - old_calls) / n
        new_avg_hour  = old_hour  + (hour             - old_hour)  / n
        new_avg_rate  = old_rate  + (calls_per_minute - old_rate)  / n

        conn.execute("""
            UPDATE user_baselines
            SET avg_calls_per_session = ?,
                avg_hour              = ?,
                avg_rate_per_minute   = ?,
                role                  = ?,
                session_count         = ?,
                updated_at            = CURRENT_TIMESTAMP
            WHERE user_id = ?
        """, (round(new_avg_calls, 2), round(new_avg_hour, 2),
              round(new_avg_rate, 2), role, n, user_id))
    else:
        conn.execute("""
            INSERT INTO user_baselines
            (user_id, role, avg_calls_per_session, avg_hour,
             avg_rate_per_minute, session_count)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (user_id, role, total_calls, hour, calls_per_minute))

    conn.commit()
    conn.close()


# ── Demo user store ────────────────────────────────────────────────────────────
# In production this would be LDAP / Active Directory / OAuth.
# For demo: plain dict. All passwords are "pass123" except attacker.

USERS: dict[str, dict] = {
    "alice":    {"password": "pass123", "role": "junior_analyst",    "name": "Alice Chen"},
    "bob":      {"password": "pass123", "role": "it_admin",          "name": "Bob Singh"},
    "carol":    {"password": "pass123", "role": "security_analyst",  "name": "Carol Wu"},
    "dave":     {"password": "pass123", "role": "finance_staff",     "name": "Dave Patel"},
    "eve":      {"password": "pass123", "role": "compliance_officer","name": "Eve Nair"},
    "frank":    {"password": "pass123", "role": "executive",         "name": "Frank Mehta"},
    "grace":    {"password": "pass123", "role": "hr_staff",          "name": "Grace Kim"},
    "attacker": {"password": "hacked1", "role": "junior_analyst",    "name": "Attacker (stolen creds)"},
}


def authenticate_user(username: str, password: str) -> dict | None:
    """Returns user dict on success, None on failure."""
    user = USERS.get(username.lower())
    if user and user["password"] == password:
        return {"username": username.lower(), **user}
    return None


if __name__ == "__main__":
    init_db()
    print("Database ready.")
    print(f"Demo users: {list(USERS.keys())} (all password: pass123, attacker: hacked1)")
