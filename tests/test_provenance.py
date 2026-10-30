"""Tests for provenance label computation.

Effective labels are computed by walking the provenance graph, so this walk is
security-critical: it is what stops a derived report from laundering the label
of the patient record it came from.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agentgate.exceptions import StorageError
from agentgate.models import SecurityLabel
from agentgate.provenance import Provenance
from agentgate.store import Store
from data.seed_data import seed_demo_data

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def seeded_store(tmp_path):
    store = Store(tmp_path / "provenance.sqlite3")
    seed_demo_data(store)
    return store


def test_effective_label_walks_the_whole_chain(seeded_store):
    """REPORT-0001 derives from the patient record, so it resolves as restricted."""
    with seeded_store.transaction(immediate=False) as conn:
        assert (
            Provenance(seeded_store).effective_label(conn, "REPORT-0001")
            is SecurityLabel.PATIENT_RESTRICTED
        )
        assert Provenance(seeded_store).effective_label(conn, "PUBLIC-0001") is SecurityLabel.PUBLIC


def test_a_missing_artifact_fails_closed(seeded_store):
    with seeded_store.transaction(immediate=False) as conn:
        with pytest.raises(StorageError, match="Missing artifact in provenance"):
            Provenance(seeded_store).effective_label(conn, "NOT-A-REAL-ARTIFACT")


def test_a_missing_source_fails_closed_rather_than_dropping_a_label(seeded_store):
    """A dangling source must raise, never silently lower the derived label."""
    with seeded_store.transaction() as conn:
        seeded_store.insert_artifact(
            conn,
            artifact_id="REPORT-DANGLING",
            artifact_type="report",
            content="Derived from a record that is later unavailable.",
            label=SecurityLabel.PUBLIC,
            creator_id="seed_system",
            session_id="demo-session",
            source_ids=("LAB-0001",),
        )

    # Break the chain the way a tampered database would, on a connection that does
    # not enforce foreign keys; the application's own connections always do.
    raw = sqlite3.connect(str(seeded_store.path), isolation_level=None)
    try:
        raw.execute("UPDATE artifact_sources SET source_id='GONE-0001' WHERE artifact_id='REPORT-DANGLING'")
    finally:
        raw.close()

    with seeded_store.transaction(immediate=False) as conn:
        with pytest.raises(StorageError, match="Missing artifact in provenance"):
            Provenance(seeded_store).effective_label(conn, "REPORT-DANGLING")


def test_a_provenance_cycle_is_detected_instead_of_recursing_forever(seeded_store):
    with seeded_store.transaction() as conn:
        seeded_store.insert_artifact(
            conn,
            artifact_id="CYCLE-A",
            artifact_type="report",
            content="First half of a cycle.",
            label=SecurityLabel.INTERNAL,
            creator_id="seed_system",
            session_id="demo-session",
            source_ids=(),
        )
        seeded_store.insert_artifact(
            conn,
            artifact_id="CYCLE-B",
            artifact_type="report",
            content="Second half of a cycle.",
            label=SecurityLabel.INTERNAL,
            creator_id="seed_system",
            session_id="demo-session",
            source_ids=("CYCLE-A",),
        )
        # Close the loop directly; the normal save path cannot produce this.
        conn.execute("INSERT INTO artifact_sources(artifact_id, source_id) VALUES('CYCLE-A','CYCLE-B')")

    with seeded_store.transaction(immediate=False) as conn:
        with pytest.raises(StorageError, match="Cycle detected in provenance"):
            Provenance(seeded_store).effective_label(conn, "CYCLE-A")


def test_graph_dot_renders_every_artifact_with_its_effective_label(seeded_store):
    """The dashboard graph must show the resolved label, not the stored one."""
    with seeded_store.transaction(immediate=False) as conn:
        dot = Provenance(seeded_store).graph_dot(conn)

    assert dot.startswith("digraph provenance {")
    assert dot.rstrip().endswith("}")
    for artifact_id in ("PUBLIC-0001", "INTERNAL-0001", "BILL-0001", "LAB-0001", "REPORT-0001"):
        assert artifact_id in dot
    # The derived report shows the inherited label and the edge it inherited through.
    assert "REPORT-0001\\nPATIENT_RESTRICTED" in dot
    assert '"LAB-0001" -> "REPORT-0001";' in dot
