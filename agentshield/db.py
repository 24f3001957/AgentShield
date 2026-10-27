"""SQLite persistence for tool calls, approvals, authorizations and audit events.

A single connection is shared by the whole process. Writes run inside
``BEGIN IMMEDIATE`` transactions guarded by a re-entrant lock, which is what
makes approval consumption atomic: exactly one of two concurrent consumers can
succeed in moving the row out of its pre-consumption state.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator, Sequence

SCHEMA = """
CREATE TABLE IF NOT EXISTS sandbox_files (
    path            TEXT PRIMARY KEY,
    content         TEXT NOT NULL,
    classification  TEXT NOT NULL
                    CHECK (classification IN ('public', 'internal', 'restricted'))
);

CREATE TABLE IF NOT EXISTS tool_calls (
    request_id       TEXT PRIMARY KEY,
    actor_id         TEXT NOT NULL,
    session_id       TEXT NOT NULL,
    tool_name        TEXT NOT NULL,
    operation        TEXT NOT NULL,
    payload_json     TEXT NOT NULL,
    state            TEXT NOT NULL,
    decision         TEXT,
    reason_code      TEXT,
    policy_version   TEXT,
    approval_id      TEXT,
    authorization_id TEXT,
    execution_id     TEXT,
    detail           TEXT,
    created_at       REAL NOT NULL,
    updated_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id  TEXT PRIMARY KEY,
    request_id   TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    binding_json TEXT NOT NULL,
    state        TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    approver     TEXT,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    decided_at   REAL,
    consumed_at  REAL,
    executed_at  REAL
);

CREATE TABLE IF NOT EXISTS authorizations (
    authorization_id TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    kind             TEXT NOT NULL,
    token            TEXT NOT NULL,
    state            TEXT NOT NULL,
    issued_at        REAL NOT NULL,
    expires_at       REAL NOT NULL,
    consumed_at      REAL
);

CREATE TABLE IF NOT EXISTS execution_ledger (
    execution_id     TEXT PRIMARY KEY,
    request_id       TEXT NOT NULL,
    authorization_id TEXT NOT NULL,
    approval_id      TEXT,
    actor_id         TEXT NOT NULL,
    tool_name        TEXT NOT NULL,
    operation        TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    summary          TEXT NOT NULL,
    detail           TEXT,
    executed_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS mock_outbox (
    message_id TEXT PRIMARY KEY,
    recipient  TEXT NOT NULL,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    actor_id   TEXT NOT NULL,
    session_id TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS mock_transfers (
    transfer_id    TEXT PRIMARY KEY,
    resource       TEXT NOT NULL,
    destination    TEXT NOT NULL,
    classification TEXT NOT NULL,
    actor_id       TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    created_at     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    seq          INTEGER PRIMARY KEY,
    event_type   TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    event_hash   TEXT NOT NULL,
    timestamp    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evaluation_runs (
    run_id      TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    results_json TEXT NOT NULL
);
"""

#: Deterministic mock sandbox contents. ``restricted`` rows are the data the
#: policy must keep away from unapproved destinations.
SEED_FILES: Sequence[tuple[str, str, str]] = (
    (
        "/public/meeting.txt",
        "Quarterly all-hands at 14:00 in the main auditorium.",
        "public",
    ),
    (
        "/public/incident-digest.txt",
        "Weekly road-safety digest: 12 reports, none critical.",
        "public",
    ),
    (
        "/internal/sprint-notes.txt",
        "Sprint 14: gateway hardening, approval expiry, audit verifier.",
        "internal",
    ),
    (
        "/secret/acquisition.txt",
        "PROJECT MERGER: offer 4.2M USD, board vote on Friday. CONFIDENTIAL.",
        "restricted",
    ),
    (
        "/secret/employee-roster.csv",
        "name,compensation_band\nA. Rao,band-9\nM. Iyer,band-7",
        "restricted",
    ),
)


class Database:
    """Process-wide SQLite handle with schema initialization and seeding."""

    def __init__(self, path: str = "agentshield.db") -> None:
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute("PRAGMA foreign_keys = ON")
        try:
            self._conn.execute("PRAGMA journal_mode = WAL")
        except sqlite3.Error:  # pragma: no cover - in-memory DBs ignore WAL
            pass
        self.initialize()

    # -- schema -------------------------------------------------------------
    def initialize(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            existing = self._conn.execute(
                "SELECT COUNT(*) AS n FROM sandbox_files"
            ).fetchone()
            if existing["n"] == 0:
                self._conn.executemany(
                    "INSERT INTO sandbox_files (path, content, classification) "
                    "VALUES (?, ?, ?)",
                    list(SEED_FILES),
                )

    # -- accessors ----------------------------------------------------------
    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a write transaction atomically (``BEGIN IMMEDIATE``)."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(params))

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, tuple(params)).fetchall())

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchone()

    def count(self, table: str, where: str = "", params: Sequence[Any] = ()) -> int:
        sql = f"SELECT COUNT(*) AS n FROM {table}"
        if where:
            sql += f" WHERE {where}"
        row = self.query_one(sql, params)
        return int(row["n"]) if row else 0

    def backup_to(self, path: str) -> "Database":
        """Write a consistent copy of this database (WAL-safe) to *path*."""
        target = Database(path)
        with self._lock:
            self._conn.backup(target.connection)
        return target

    def close(self) -> None:
        with self._lock:
            self._conn.close()
