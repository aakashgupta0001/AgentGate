from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from agentgate.exceptions import StorageError
from agentgate.models import Artifact, SecurityLabel

SCHEMA_VERSION = "1"


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        try:
            with self.transaction() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS schema_metadata (
                        key TEXT PRIMARY KEY, value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS artifacts (
                        artifact_id TEXT PRIMARY KEY,
                        artifact_type TEXT NOT NULL,
                        content TEXT NOT NULL,
                        label TEXT NOT NULL CHECK(label IN ('PUBLIC','INTERNAL','CONFIDENTIAL','PATIENT_RESTRICTED')),
                        creator_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        session_id TEXT,
                        version INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE TABLE IF NOT EXISTS artifact_sources (
                        artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
                        source_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                        PRIMARY KEY(artifact_id, source_id),
                        CHECK(artifact_id <> source_id)
                    );
                    CREATE TABLE IF NOT EXISTS workflow_sessions (
                        session_id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        agent_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        resumed_at TEXT
                    );
                    CREATE TABLE IF NOT EXISTS session_reads (
                        session_id TEXT NOT NULL REFERENCES workflow_sessions(session_id),
                        artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                        read_at TEXT NOT NULL,
                        PRIMARY KEY(session_id, artifact_id)
                    );
                    CREATE TABLE IF NOT EXISTS mock_inbox (
                        message_id TEXT PRIMARY KEY,
                        recipient_id TEXT NOT NULL,
                        artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                        label TEXT NOT NULL,
                        delivered_at TEXT NOT NULL,
                        result TEXT NOT NULL CHECK(result = 'DELIVERED')
                    );
                    CREATE TABLE IF NOT EXISTS audit_events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        payload_json TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS classification_history (
                        change_id TEXT PRIMARY KEY,
                        artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                        old_label TEXT NOT NULL,
                        new_label TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        policy_hash TEXT NOT NULL,
                        changed_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
                    CREATE INDEX IF NOT EXISTS idx_artifacts_label ON artifacts(label);
                    CREATE INDEX IF NOT EXISTS idx_sources_source ON artifact_sources(source_id);
                    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(event_id);
                    CREATE INDEX IF NOT EXISTS idx_inbox_recipient ON mock_inbox(recipient_id);
                    """
                )
                conn.execute(
                    "INSERT OR IGNORE INTO schema_metadata(key, value) VALUES('schema_version', ?)",
                    (SCHEMA_VERSION,),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO schema_metadata(key, value) VALUES('audit_head', ?)",
                    ("0" * 64,),
                )
                version = conn.execute(
                    "SELECT value FROM schema_metadata WHERE key='schema_version'"
                ).fetchone()["value"]
                if version != SCHEMA_VERSION:
                    raise StorageError(f"Unsupported database schema version: {version}")
        except sqlite3.Error as exc:
            raise StorageError(f"Could not initialize SQLite database: {exc}") from exc

    def create_session(self, conn: sqlite3.Connection, session_id: str, actor_id: str, agent_id: str) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO workflow_sessions(session_id, actor_id, agent_id, created_at) VALUES(?,?,?,?)",
            (session_id, actor_id, agent_id, _now()),
        )

    def get_artifact(self, conn: sqlite3.Connection, artifact_id: str) -> Artifact | None:
        row = conn.execute("SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)).fetchone()
        if row is None:
            return None
        sources = conn.execute(
            "SELECT source_id FROM artifact_sources WHERE artifact_id=? ORDER BY source_id",
            (artifact_id,),
        ).fetchall()
        return Artifact(
            artifact_id=row["artifact_id"],
            artifact_type=row["artifact_type"],
            content=row["content"],
            label=SecurityLabel(row["label"]),
            source_ids=tuple(item["source_id"] for item in sources),
            creator_id=row["creator_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            session_id=row["session_id"],
        )

    def list_artifacts(self, conn: sqlite3.Connection) -> list[Artifact]:
        rows = conn.execute("SELECT artifact_id FROM artifacts ORDER BY created_at, artifact_id").fetchall()
        return [artifact for row in rows if (artifact := self.get_artifact(conn, row["artifact_id"]))]

    def insert_artifact(
        self,
        conn: sqlite3.Connection,
        *,
        artifact_id: str,
        artifact_type: str,
        content: str,
        label: SecurityLabel,
        creator_id: str,
        session_id: str,
        source_ids: tuple[str, ...],
    ) -> Artifact:
        timestamp = _now()
        conn.execute(
            """INSERT INTO artifacts(artifact_id, artifact_type, content, label, creator_id, created_at, session_id)
               VALUES(?,?,?,?,?,?,?)""",
            (artifact_id, artifact_type, content, label.value, creator_id, timestamp, session_id),
        )
        conn.executemany(
            "INSERT INTO artifact_sources(artifact_id, source_id) VALUES(?,?)",
            [(artifact_id, source_id) for source_id in source_ids],
        )
        artifact = self.get_artifact(conn, artifact_id)
        if artifact is None:
            raise StorageError(f"Inserted artifact could not be reloaded: {artifact_id}")
        return artifact

    def sources_for_session(self, conn: sqlite3.Connection, session_id: str) -> tuple[str, ...]:
        rows = conn.execute(
            "SELECT artifact_id FROM session_reads WHERE session_id=? ORDER BY artifact_id",
            (session_id,),
        ).fetchall()
        return tuple(row["artifact_id"] for row in rows)

    def record_read(self, conn: sqlite3.Connection, session_id: str, artifact_id: str) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO session_reads(session_id, artifact_id, read_at) VALUES(?,?,?)",
            (session_id, artifact_id, _now()),
        )

    def reload_session(self, session_id: str) -> dict:
        with self.transaction() as conn:
            row = conn.execute("SELECT * FROM workflow_sessions WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                raise StorageError(f"Unknown workflow session: {session_id}")
            conn.execute(
                "UPDATE workflow_sessions SET resumed_at=? WHERE session_id=?",
                (_now(), session_id),
            )
            reads = self.sources_for_session(conn, session_id)
            artifacts = [
                self.get_artifact(conn, row["artifact_id"])
                for row in conn.execute(
                    """SELECT DISTINCT a.artifact_id FROM artifacts a
                       LEFT JOIN session_reads r ON r.artifact_id=a.artifact_id AND r.session_id=?
                       WHERE a.session_id=? OR r.artifact_id IS NOT NULL
                       ORDER BY a.created_at""",
                    (session_id, session_id),
                ).fetchall()
            ]
            return {"session": dict(row), "reads": reads, "artifacts": [a for a in artifacts if a]}

    def inbox(self, conn: sqlite3.Connection) -> list[dict]:
        return [dict(row) for row in conn.execute("SELECT * FROM mock_inbox ORDER BY delivered_at DESC")]

    def metrics(self, conn: sqlite3.Connection) -> dict[str, int]:
        count = lambda sql: int(conn.execute(sql).fetchone()[0])
        return {
            "artifacts": count("SELECT COUNT(*) FROM artifacts"),
            "decisions": count("SELECT COUNT(*) FROM audit_events WHERE json_extract(payload_json, '$.event_type')='AUTHORIZATION_DECISION'"),
            "allowed": count("SELECT COUNT(*) FROM audit_events WHERE json_extract(payload_json, '$.event_type')='AUTHORIZATION_DECISION' AND json_extract(payload_json, '$.status')='ALLOW'"),
            "denied": count("SELECT COUNT(*) FROM audit_events WHERE json_extract(payload_json, '$.event_type')='AUTHORIZATION_DECISION' AND json_extract(payload_json, '$.status')='DENY'"),
            "deliveries": count("SELECT COUNT(*) FROM mock_inbox"),
            "blocked_deliveries": count("SELECT COUNT(*) FROM audit_events WHERE json_extract(payload_json, '$.event_type')='AUTHORIZATION_DECISION' AND json_extract(payload_json, '$.status')='DENY' AND json_extract(payload_json, '$.operation')='DELIVER'"),
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"
