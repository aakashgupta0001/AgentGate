from collections.abc import Iterable

from agentgate.models import SecurityLabel

_RANK = {
    SecurityLabel.PUBLIC: 0,
    SecurityLabel.INTERNAL: 1,
    SecurityLabel.CONFIDENTIAL: 2,
    SecurityLabel.PATIENT_RESTRICTED: 3,
}


def label_rank(label: SecurityLabel) -> int:
    try:
        return _RANK[label]
    except KeyError as exc:
        raise ValueError(f"Unknown security label: {label!r}") from exc


def max_label(labels: Iterable[SecurityLabel]) -> SecurityLabel:
    values = tuple(labels)
    if not values:
        raise ValueError("At least one security label is required")
    return max(values, key=label_rank)


def can_flow_to(source_label: SecurityLabel, recipient_clearance: SecurityLabel) -> bool:
    return label_rank(source_label) <= label_rank(recipient_clearance)
