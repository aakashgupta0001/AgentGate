from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml

from agentgate.exceptions import PolicyError
from agentgate.models import ActionType, PolicyConfig, SecurityLabel


def _freeze_sequences(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(_freeze_sequences(item) for item in value)
    if isinstance(value, dict):
        return {key: _freeze_sequences(item) for key, item in value.items()}
    return value


def _normalize_policy(payload: dict) -> dict:
    normalized = {**payload}
    normalized["identities"] = {
        key: {**rule, "operations": tuple(ActionType(value) for value in rule["operations"])}
        for key, rule in payload["identities"].items()
    }
    normalized["agents"] = {
        key: {**rule, "operations": tuple(ActionType(value) for value in rule["operations"])}
        for key, rule in payload["agents"].items()
    }
    normalized["recipients"] = {
        key: {**rule, "clearance": SecurityLabel(rule["clearance"])}
        for key, rule in payload["recipients"].items()
    }
    normalized["declassification_targets"] = {
        SecurityLabel(source): tuple(SecurityLabel(target) for target in targets)
        for source, targets in payload["declassification_targets"].items()
    }
    return _freeze_sequences(normalized)


def resource_matches(patterns: tuple[str, ...], resource_id: str) -> bool:
    from fnmatch import fnmatchcase

    return any(fnmatchcase(resource_id, pattern) for pattern in patterns)


class PolicyEngine:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.config: PolicyConfig
        self.policy_hash: str
        self.reload()

    def reload(self) -> str:
        try:
            raw_bytes = self.path.read_bytes()
            payload = yaml.safe_load(raw_bytes)
            if not isinstance(payload, dict):
                raise ValueError("policy document must be a mapping")
            self.config = PolicyConfig.model_validate(_normalize_policy(payload))
            self.policy_hash = hashlib.sha256(raw_bytes).hexdigest()
        except (OSError, yaml.YAMLError, TypeError, ValueError, KeyError) as exc:
            raise PolicyError(f"Trusted policy unavailable or invalid at {self.path}: {exc}") from exc
        return self.policy_hash

    def permits_identity(self, actor_id: str, action: ActionType, resource_id: str, purpose: str) -> bool:
        rule = self.config.identities.get(actor_id)
        return bool(
            rule
            and action in rule.operations
            and resource_matches(rule.resources, resource_id)
            and (not rule.purposes or purpose in rule.purposes)
        )

    def permits_agent(self, agent_id: str, action: ActionType, resource_id: str) -> bool:
        rule = self.config.agents.get(agent_id)
        return bool(rule and action in rule.operations and resource_matches(rule.resources, resource_id))

    def recipient(self, recipient_id: str):
        return self.config.recipients.get(recipient_id)

    def can_declassify(self, actor_id: str, source, target) -> bool:
        identity = self.config.identities.get(actor_id)
        if not identity or not set(identity.roles).intersection(self.config.declassification_roles):
            return False
        return target in self.config.declassification_targets.get(source, ())
