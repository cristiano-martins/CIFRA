import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    target TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    result TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(settings.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def save_scan(scan_type: str, target: str, result: dict) -> str:
    scan_id = str(uuid.uuid4())
    risk = result.get("risk", {})
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scans (id, type, target, risk_score, risk_level, result, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                scan_type,
                target,
                risk.get("score", 0),
                risk.get("level", "LOW"),
                json.dumps(result, ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    return scan_id


def get_history(limit: int = 30) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, type, target, risk_score, risk_level, created_at "
            "FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    data = dict(row)
    data["result"] = json.loads(data["result"])
    return data


def delete_scan(scan_id: str) -> bool:
    with get_conn() as conn:
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return cursor.rowcount > 0


def delete_all() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM scans")
