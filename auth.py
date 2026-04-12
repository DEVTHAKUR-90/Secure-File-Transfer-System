"""
auth.py
=======
Authentication and Role-Based Access Control (RBAC) module.

Implements:
  - Argon2id password hashing (winner of Password Hashing Competition)
  - Salted password storage  — plain-text passwords NEVER touch the DB
  - User registration and login
  - RBAC roles: admin / sender / receiver / viewer
  - Secure session token generation and validation
  - SQLite user store (swap for PostgreSQL in production)

Security notes:
  - Argon2id is resistant to GPU/ASIC brute-force and side-channel attacks
  - Each password gets a unique random salt (built into argon2-cffi)
  - Session tokens are 32-byte CSPRNG values stored as hex
  - Tokens expire after SESSION_TTL_SECONDS
"""

import os
import sqlite3
import secrets
import time
from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_PATH             = os.environ.get("AUTH_DB_PATH", "users.db")
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL", 3600))   # 1 hour

# Argon2id parameters (OWASP recommended minimums)
_ph = PasswordHasher(
    time_cost=2,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

# ---------------------------------------------------------------------------
# RBAC role definitions
# ---------------------------------------------------------------------------
ROLES = {
    "admin":    {"can_send": True,  "can_receive": True,  "can_view_logs": True,  "can_manage_users": True},
    "sender":   {"can_send": True,  "can_receive": False, "can_view_logs": False, "can_manage_users": False},
    "receiver": {"can_send": False, "can_receive": True,  "can_view_logs": False, "can_manage_users": False},
    "viewer":   {"can_send": False, "can_receive": False, "can_view_logs": True,  "can_manage_users": False},
}


# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------

def init_db():
    """Create tables if they don't exist. Call once at app startup."""
    conn = _get_conn()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            hash        TEXT    NOT NULL,
            role        TEXT    NOT NULL DEFAULT 'receiver',
            created_at  TEXT    NOT NULL,
            is_active   INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT    PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            username    TEXT    NOT NULL,
            role        TEXT    NOT NULL,
            created_at  REAL    NOT NULL,
            expires_at  REAL    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS rsa_keys (
            user_id     INTEGER PRIMARY KEY,
            public_pem  TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()

    # Create default admin if no users exist
    _seed_admin()


def _seed_admin():
    """Create a default admin account on first run."""
    admin_pass = os.environ.get("ADMIN_PASSWORD", "Admin@1234")
    try:
        register_user("admin", admin_pass, role="admin")
        print("[AUTH] Default admin created. Change the password immediately!")
    except ValueError:
        pass   # admin already exists


def _get_conn():
    return sqlite3.connect(DB_PATH)


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

def register_user(username: str, password: str, role: str = "receiver") -> dict:
    """
    Register a new user. Raises ValueError if username already exists
    or role is invalid.

    ⚠️  The raw password is hashed immediately and discarded.
        The plain-text password NEVER reaches the database.
    """
    if role not in ROLES:
        raise ValueError(f"Invalid role '{role}'. Choose from: {list(ROLES)}")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    # Argon2id hash — includes random salt internally
    pw_hash = _ph.hash(password)

    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, hash, role, created_at) VALUES (?,?,?,?)",
            (username, pw_hash, role, datetime.utcnow().isoformat()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError(f"Username '{username}' is already taken.")
    finally:
        conn.close()

    return {"username": username, "role": role, "status": "registered"}


def login_user(username: str, password: str) -> dict:
    """
    Verify credentials and issue a session token.
    Returns session dict on success, raises ValueError on failure.
    """
    conn = _get_conn()
    row = conn.execute(
        "SELECT id, hash, role, is_active FROM users WHERE username=?",
        (username,),
    ).fetchone()
    conn.close()

    if not row:
        raise ValueError("Invalid username or password.")

    user_id, pw_hash, role, is_active = row

    if not is_active:
        raise ValueError("Account is disabled. Contact your administrator.")

    try:
        _ph.verify(pw_hash, password)
    except (VerifyMismatchError, VerificationError):
        raise ValueError("Invalid username or password.")

    # Re-hash if Argon2 parameters changed (transparent upgrade)
    if _ph.check_needs_rehash(pw_hash):
        new_hash = _ph.hash(password)
        conn = _get_conn()
        conn.execute("UPDATE users SET hash=? WHERE id=?", (new_hash, user_id))
        conn.commit()
        conn.close()

    token = _create_session(user_id, username, role)
    return {"token": token, "username": username, "role": role, "permissions": ROLES[role]}


def _create_session(user_id: int, username: str, role: str) -> str:
    """Generate a CSPRNG session token and persist it."""
    token = secrets.token_hex(32)   # 256-bit random token
    now   = time.time()
    expires = now + SESSION_TTL_SECONDS

    conn = _get_conn()
    conn.execute(
        "INSERT INTO sessions (token, user_id, username, role, created_at, expires_at) VALUES (?,?,?,?,?,?)",
        (token, user_id, username, role, now, expires),
    )
    conn.commit()
    conn.close()
    return token


def validate_session(token: str) -> dict | None:
    """
    Validate a session token. Returns user info dict or None if invalid/expired.
    """
    if not token:
        return None

    conn = _get_conn()
    row = conn.execute(
        "SELECT username, role, expires_at FROM sessions WHERE token=?",
        (token,),
    ).fetchone()
    conn.close()

    if not row:
        return None

    username, role, expires_at = row
    if time.time() > expires_at:
        logout_user(token)
        return None

    return {"username": username, "role": role, "permissions": ROLES.get(role, {})}


def logout_user(token: str):
    """Invalidate a session token."""
    conn = _get_conn()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()


def get_all_users() -> list:
    """Return all users (admin only)."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, username, role, created_at, is_active FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return [{"id": r[0], "username": r[1], "role": r[2], "created_at": r[3], "active": bool(r[4])} for r in rows]


def store_user_public_key(user_id: int, public_pem: str):
    """Store a user's RSA public key for key-exchange."""
    conn = _get_conn()
    conn.execute(
        "INSERT OR REPLACE INTO rsa_keys (user_id, public_pem) VALUES (?,?)",
        (user_id, public_pem),
    )
    conn.commit()
    conn.close()


def get_user_public_key(username: str) -> str | None:
    """Retrieve the RSA public key for a given username."""
    conn = _get_conn()
    row = conn.execute(
        """SELECT rk.public_pem FROM rsa_keys rk
           JOIN users u ON u.id = rk.user_id
           WHERE u.username=?""",
        (username,),
    ).fetchone()
    conn.close()
    return row[0] if row else None


def require_permission(token: str, permission: str):
    """
    Decorator-style helper. Raises PermissionError if the session lacks
    the required RBAC permission.
    """
    user = validate_session(token)
    if not user:
        raise PermissionError("Session invalid or expired. Please log in.")
    if not user["permissions"].get(permission):
        raise PermissionError(f"Your role '{user['role']}' cannot perform: {permission}")
    return user
