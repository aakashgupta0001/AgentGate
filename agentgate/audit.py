from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

GENESIS_HASH = "0" * 64


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    def append(self, conn: sqlite3.Connection, payload: dict) -> dict:
        immutable = dict(payload)
        immutable.setdefault("event_id", str(uuid4()))
        immutable.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        payload_json = canonical_json(immutable)
        row = conn.execute("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").fetchone()
        previous_hash = row["event_hash"] if row else GENESIS_HASH
        event_hash = hashlib.sha256((payload_json + "\n" + previous_hash).encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT INTO audit_events(event_id,payload_json,previous_hash,event_hash) VALUES(?,?,?,?)",
            (immutable["event_id"], payload_json, previous_hash, event_hash),
        )
        conn.execute(
            "INSERT INTO schema_metadata(key,value) VALUES('audit_head',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (event_hash,),
        )
        return {**immutable, "previous_hash": previous_hash, "event_hash": event_hash}

    def events(self, conn: sqlite3.Connection) -> list[dict]:
        return [
            {
                **json.loads(row["payload_json"]),
                "sequence": row["sequence"],
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in conn.execute("SELECT * FROM audit_events ORDER BY sequence")
        ]

    def verify(self, conn: sqlite3.Connection) -> dict:
        expected_previous = GENESIS_HASH
        rows = conn.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        for expected_sequence, row in enumerate(rows, start=1):
            if row["sequence"] != expected_sequence:
                return {"valid": False, "checked": expected_sequence - 1, "reason": "event ordering gap"}
            if row["previous_hash"] != expected_previous:
                return {"valid": False, "checked": expected_sequence - 1, "reason": "previous hash mismatch"}
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                return {"valid": False, "checked": expected_sequence - 1, "reason": "invalid event payload"}
            canonical = canonical_json(payload)
            if canonical != row["payload_json"]:
                return {"valid": False, "checked": expected_sequence - 1, "reason": "non-canonical event payload"}
            calculated = hashlib.sha256((canonical + "\n" + expected_previous).encode("utf-8")).hexdigest()
            if calculated != row["event_hash"]:
                return {"valid": False, "checked": expected_sequence, "reason": "event hash mismatch"}
            expected_previous = calculated
        stored_head = conn.execute(
            "SELECT value FROM schema_metadata WHERE key='audit_head'"
        ).fetchone()
        if stored_head is None or stored_head["value"] != expected_previous:
            return {"valid": False, "checked": len(rows), "reason": "stored chain head mismatch"}
        return {"valid": True, "checked": len(rows), "head": expected_previous, "reason": "chain valid"}
