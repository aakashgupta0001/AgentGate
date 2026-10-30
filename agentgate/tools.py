from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from agentgate.models import Artifact, SecurityLabel
from agentgate.labels import max_label
from agentgate.provenance import Provenance
from agentgate.store import Store, new_id


class ProtectedTools:
    """Local-only tools. The gateway is the only application caller."""

    def __init__(self, store: Store):
        self.store = store

    def read_document(self, conn: sqlite3.Connection, session_id: str, artifact_id: str) -> Artifact:
        artifact = self.store.get_artifact(conn, artifact_id)
        if artifact is None:
            raise LookupError("Requested document does not exist")
        self.store.record_read(conn, session_id, artifact_id)
        return artifact

    def save_report(
        self,
        conn: sqlite3.Connection,
        *,
        session_id: str,
        actor_id: str,
        source_ids: tuple[str, ...],
        content: str,
    ) -> Artifact:
        labels = [Provenance(self.store).effective_label(conn, source_id) for source_id in source_ids]
        label = max_label(labels)
        report_id = new_id("REPORT")
        return self.store.insert_artifact(
            conn,
            artifact_id=report_id,
            artifact_type="report",
            content=content,
            label=label,
            creator_id=actor_id,
            session_id=session_id,
            source_ids=source_ids,
        )

    def deliver(
        self,
        conn: sqlite3.Connection,
        *,
        recipient_id: str,
        artifact_id: str,
        label: SecurityLabel,
    ) -> dict:
        message = {
            "message_id": f"MSG-{uuid4().hex[:12]}",
            "recipient_id": recipient_id,
            "artifact_id": artifact_id,
            "label": label.value,
            "delivered_at": datetime.now(timezone.utc).isoformat(),
            "result": "DELIVERED",
        }
        conn.execute(
            """INSERT INTO mock_inbox(message_id,recipient_id,artifact_id,label,delivered_at,result)
               VALUES(:message_id,:recipient_id,:artifact_id,:label,:delivered_at,:result)""",
            message,
        )
        return message
