from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator


class SecurityLabel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PATIENT_RESTRICTED = "PATIENT_RESTRICTED"


class ActionType(str, Enum):
    READ = "READ"
    SAVE = "SAVE"
    DELIVER = "DELIVER"


class DecisionStatus(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


Identifier = Annotated[StrictStr, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.@+-]+$")]


class ActionProposal(StrictModel):
    action_id: Identifier = Field(default_factory=lambda: str(uuid4()))
    session_id: Identifier
    actor_id: Identifier
    agent_id: Identifier
    action_type: ActionType
    resource_id: Identifier
    recipient_id: Identifier | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    purpose: Annotated[StrictStr, Field(min_length=3, max_length=120)]
    source_ids: tuple[Identifier, ...] = ()
    content: Annotated[StrictStr, Field(max_length=100_000)] | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_action_shape(self) -> "ActionProposal":
        if self.action_type is ActionType.DELIVER and not self.recipient_id:
            raise ValueError("recipient_id is required for delivery")
        if self.action_type is not ActionType.DELIVER and self.recipient_id is not None:
            raise ValueError("recipient_id is only valid for delivery")
        if self.action_type is ActionType.SAVE and self.content is None:
            raise ValueError("content is required when saving a report")
        if self.action_type is not ActionType.SAVE and (self.content is not None or self.source_ids):
            raise ValueError("content and source_ids are only valid when saving a report")
        return self


class Artifact(StrictModel):
    artifact_id: Identifier
    artifact_type: Annotated[StrictStr, Field(min_length=1, max_length=40)]
    content: StrictStr
    label: SecurityLabel
    source_ids: tuple[Identifier, ...] = ()
    creator_id: Identifier
    created_at: datetime
    session_id: Identifier | None = None


class IdentityRule(StrictModel):
    roles: tuple[StrictStr, ...]
    operations: tuple[ActionType, ...]
    resources: tuple[StrictStr, ...]
    purposes: tuple[StrictStr, ...] = ()


class AgentRule(StrictModel):
    operations: tuple[ActionType, ...]
    resources: tuple[StrictStr, ...]


class RecipientRule(StrictModel):
    clearance: SecurityLabel
    purposes: tuple[StrictStr, ...]
    resources: tuple[StrictStr, ...]


class PolicyConfig(StrictModel):
    version: Annotated[StrictStr, Field(min_length=1)]
    identities: dict[Identifier, IdentityRule]
    agents: dict[Identifier, AgentRule]
    recipients: dict[Identifier, RecipientRule]
    declassification_roles: tuple[StrictStr, ...]
    declassification_targets: dict[SecurityLabel, tuple[SecurityLabel, ...]]


class Decision(StrictModel):
    decision_id: Identifier = Field(default_factory=lambda: str(uuid4()))
    action_id: Identifier
    status: DecisionStatus
    reason_code: Identifier
    explanation: StrictStr
    policy_hash: StrictStr
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditEvent(StrictModel):
    event_id: Identifier = Field(default_factory=lambda: str(uuid4()))
    event_type: Identifier
    action_id: Identifier | None = None
    actor_id: Identifier | None = None
    resource_id: Identifier | None = None
    status: DecisionStatus | None = None
    reason_code: Identifier | None = None
    policy_hash: StrictStr = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[StrictStr, StrictStr] = Field(default_factory=dict)
