import sqlite3

from agentgate.exceptions import StorageError
from agentgate.labels import max_label
from agentgate.models import SecurityLabel
from agentgate.store import Store


class Provenance:
    def __init__(self, store: Store):
        self.store = store

    def effective_label(self, conn: sqlite3.Connection, artifact_id: str, visiting: set[str] | None = None) -> SecurityLabel:
        active = set() if visiting is None else set(visiting)
        if artifact_id in active:
            raise StorageError(f"Cycle detected in provenance at {artifact_id}")
        artifact = self.store.get_artifact(conn, artifact_id)
        if artifact is None:
            raise StorageError(f"Missing artifact in provenance: {artifact_id}")
        active.add(artifact_id)
        labels = [artifact.label]
        for source_id in artifact.source_ids:
            labels.append(self.effective_label(conn, source_id, active))
        return max_label(labels)

    def graph_dot(self, conn: sqlite3.Connection) -> str:
        lines = ["digraph provenance {", '  rankdir="LR";', '  node [shape=box, style="rounded,filled", fillcolor="#eef4ff"];']
        for artifact in self.store.list_artifacts(conn):
            effective_label = self.effective_label(conn, artifact.artifact_id)
            safe_label = f"{artifact.artifact_id}\\n{effective_label.value}".replace('"', "'")
            lines.append(f'  "{artifact.artifact_id}" [label="{safe_label}"];')
            for source_id in artifact.source_ids:
                lines.append(f'  "{source_id}" -> "{artifact.artifact_id}";')
        lines.append("}")
        return "\n".join(lines)
