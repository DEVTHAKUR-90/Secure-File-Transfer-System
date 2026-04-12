"""
audit_logger.py
===============
GRC-compliant audit logging module.

Records every security-relevant event with:
  - UTC timestamp (ISO 8601)
  - Event type / severity
  - Actor (username)
  - IP address
  - File metadata (name, size, hash)
  - Outcome (SUCCESS / FAILURE)
  - Detail message

Storage:
  - SQLite audit table (append-only — rows are never updated/deleted)
  - Rotating plain-text log file as a secondary record

Integrity:
  - Each row stores a SHA-256 chain hash (hash of previous row + current row data)
    so any deletion or modification of a past record is detectable.
"""

import os
import sqlite3
import hashlib
import json
from datetime import datetime, timezone

AUDIT_DB  = os.environ.get("AUDIT_DB_PATH",  "audit.db")
AUDIT_LOG = os.environ.get("AUDIT_LOG_PATH", "logs/audit.log")

# Ensure log directory exists
os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)


# ---------------------------------------------------------------------------
# Event type constants
# ---------------------------------------------------------------------------
class Event:
    LOGIN_OK      = "LOGIN_SUCCESS"
    LOGIN_FAIL    = "LOGIN_FAILURE"
    LOGOUT        = "LOGOUT"
    REGISTER      = "USER_REGISTERED"
    FILE_UPLOAD   = "FILE_UPLOAD"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"
    FILE_DELETE   = "FILE_DELETE"
    KEY_EXCHANGE  = "KEY_EXCHANGE"
    INTEGRITY_OK  = "INTEGRITY_CHECK_PASS"
    INTEGRITY_FAIL= "INTEGRITY_CHECK_FAIL"
    PERM_DENIED   = "PERMISSION_DENIED"
    TRANSFER_START= "TRANSFER_STARTED"
    TRANSFER_DONE = "TRANSFER_COMPLETE"
    TRANSFER_FAIL = "TRANSFER_FAILED"
    PARTIAL_DELETE= "PARTIAL_FILE_DELETED"


# ---------------------------------------------------------------------------
# Database initialisation
# ---------------------------------------------------------------------------

def init_audit_db():
    conn = _conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT    NOT NULL,
            event       TEXT    NOT NULL,
            severity    TEXT    NOT NULL DEFAULT 'INFO',
            username    TEXT,
            ip_address  TEXT,
            filename    TEXT,
            file_size   INTEGER,
            file_hash   TEXT,
            outcome     TEXT    NOT NULL DEFAULT 'SUCCESS',
            detail      TEXT,
            chain_hash  TEXT
        )
    """)
    conn.commit()
    conn.close()


def _conn():
    return sqlite3.connect(AUDIT_DB)


# ---------------------------------------------------------------------------
# Core logging function
# ---------------------------------------------------------------------------

def log_event(
    event:      str,
    username:   str  = "anonymous",
    ip_address: str  = "unknown",
    filename:   str  = None,
    file_size:  int  = None,
    file_hash:  str  = None,
    outcome:    str  = "SUCCESS",
    detail:     str  = "",
    severity:   str  = "INFO",
):
    """
    Append a tamper-evident audit record.
    chain_hash = SHA-256( previous_chain_hash + current_row_data )
    """
    ts = datetime.now(timezone.utc).isoformat()

    # Build the payload string for chaining
    payload = f"{ts}|{event}|{username}|{ip_address}|{filename}|{file_hash}|{outcome}|{detail}"

    # Get the last chain hash
    prev_hash = _get_last_chain_hash()
    chain_hash = hashlib.sha256(f"{prev_hash}{payload}".encode()).hexdigest()

    conn = _conn()
    conn.execute(
        """INSERT INTO audit_log
           (ts, event, severity, username, ip_address, filename, file_size,
            file_hash, outcome, detail, chain_hash)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (ts, event, severity, username, ip_address, filename, file_size,
         file_hash, outcome, detail, chain_hash),
    )
    conn.commit()
    conn.close()

    # Also write to flat log file
    _write_flat_log(ts, severity, event, username, ip_address, outcome, detail, filename)


def _get_last_chain_hash() -> str:
    conn = _conn()
    row = conn.execute(
        "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return row[0] if row else "GENESIS"


def _write_flat_log(ts, severity, event, username, ip, outcome, detail, filename):
    line = f"[{ts}] [{severity}] [{outcome}] {event} | user={username} ip={ip}"
    if filename:
        line += f" file={filename}"
    if detail:
        line += f" | {detail}"
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass   # Never let logging crash the app


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_recent_events(limit: int = 100) -> list:
    """Return the most recent *limit* audit events (newest first)."""
    conn = _conn()
    rows = conn.execute(
        """SELECT id, ts, event, severity, username, ip_address,
                  filename, file_size, file_hash, outcome, detail
           FROM audit_log ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    keys = ["id","ts","event","severity","username","ip_address",
            "filename","file_size","file_hash","outcome","detail"]
    return [dict(zip(keys, r)) for r in rows]


def get_events_by_user(username: str, limit: int = 50) -> list:
    conn = _conn()
    rows = conn.execute(
        """SELECT id, ts, event, severity, username, ip_address,
                  filename, outcome, detail
           FROM audit_log WHERE username=? ORDER BY id DESC LIMIT ?""",
        (username, limit),
    ).fetchall()
    conn.close()
    keys = ["id","ts","event","severity","username","ip_address","filename","outcome","detail"]
    return [dict(zip(keys, r)) for r in rows]


def get_stats() -> dict:
    """Aggregate statistics for the GRC dashboard."""
    conn = _conn()
    cur = conn.cursor()

    total        = cur.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    transfers    = cur.execute("SELECT COUNT(*) FROM audit_log WHERE event=?", (Event.TRANSFER_DONE,)).fetchone()[0]
    failed       = cur.execute("SELECT COUNT(*) FROM audit_log WHERE outcome='FAILURE'").fetchone()[0]
    integrity_ok = cur.execute("SELECT COUNT(*) FROM audit_log WHERE event=?", (Event.INTEGRITY_OK,)).fetchone()[0]
    integrity_fail = cur.execute("SELECT COUNT(*) FROM audit_log WHERE event=?", (Event.INTEGRITY_FAIL,)).fetchone()[0]
    login_fail   = cur.execute("SELECT COUNT(*) FROM audit_log WHERE event=?", (Event.LOGIN_FAIL,)).fetchone()[0]

    conn.close()
    return {
        "total_events":     total,
        "successful_transfers": transfers,
        "failed_events":    failed,
        "integrity_pass":   integrity_ok,
        "integrity_fail":   integrity_fail,
        "login_failures":   login_fail,
    }


def verify_chain_integrity() -> dict:
    """
    Walk the entire chain and verify each hash links correctly.
    Returns {"ok": True/False, "broken_at": row_id or None}
    """
    conn = _conn()
    rows = conn.execute(
        "SELECT id, ts, event, username, ip_address, filename, file_hash, outcome, detail, chain_hash FROM audit_log ORDER BY id ASC"
    ).fetchall()
    conn.close()

    prev = "GENESIS"
    for row in rows:
        row_id = row[0]
        ts, event, username, ip, filename, file_hash, outcome, detail, stored_hash = row[1:]
        payload   = f"{ts}|{event}|{username}|{ip}|{filename}|{file_hash}|{outcome}|{detail}"
        expected  = hashlib.sha256(f"{prev}{payload}".encode()).hexdigest()
        if expected != stored_hash:
            return {"ok": False, "broken_at": row_id}
        prev = stored_hash

    return {"ok": True, "broken_at": None}
