from __future__ import annotations

import sqlite3
import re
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ValidationError

from agentgate.audit import AuditLog
from agentgate.exceptions import PolicyError, StorageError
from agentgate.labels import can_flow_to, label_rank
from agentgate.models import ActionProposal, ActionType, Decision, DecisionStatus, SecurityLabel
from agentgate.policy import PolicyEngine, resource_matches
from agentgate.provenance import Provenance
from agentgate.store import Store
from agentgate.tools import ProtectedTools


class Gateway:
    def __init__(self, store: Store, policy: PolicyEngine, tools: ProtectedTools | None = None):
        self.store = store
        self.policy = policy
        self.tools = tools or ProtectedTools(store)
        self.audit = AuditLog()
        self.provenance = Provenance(store)

    def decide_and_execute(self, proposal: ActionProposal | dict) -> dict:
        try:
            if isinstance(proposal, ActionProposal):
                action = proposal
            else:
                if isinstance(proposal, BaseModel):
                    if proposal.__class__.model_config.get("extra") != "forbid":
                        raise ValueError("proposal model must forbid unknown fields")
                    unknown_fields = set(proposal.__class__.model_fields) - set(ActionProposal.model_fields)
                    if unknown_fields:
                        raise ValueError("proposal model contains unsupported fields")
                    payload = proposal.model_dump(mode="python")
                else:
                    payload = proposal
                if isinstance(payload, dict) and isinstance(payload.get("action_type"), Enum):
                    payload["action_type"] = payload["action_type"].value
                if isinstance(payload, dict) and isinstance(payload.get("action_type"), str):
                    payload["action_type"] = ActionType(payload["action_type"])
                if isinstance(payload, dict) and isinstance(payload.get("timestamp"), str):
                    payload["timestamp"] = datetime.fromisoformat(payload["timestamp"].replace("Z", "+00:00"))
                action = ActionProposal.model_validate(payload)
        except (ValidationError, ValueError) as exc:
            action_id = proposal.get("action_id") if isinstance(proposal, dict) else None
            safe_action_id = self._safe_action_id(action_id)
            validation_errors = exc.errors() if isinstance(exc, ValidationError) else []
            with self.store.transaction() as conn:
                self.audit.append(
                    conn,
                    {
                        "event_type": "PROPOSAL_REJECTED",
                        "action_id": safe_action_id,
                        "status": "DENY",
                        "reason_code": "DENY_INVALID_PROPOSAL",
                        "explanation": "Proposal failed strict schema validation.",
                        "policy_hash": self.policy.policy_hash,
                        "metadata": {
                            "validation_error_type": type(exc).__name__,
                            "validation_errors": ";".join(
                                f"{'.'.join(str(part) for part in error['loc'])}:{error['type']}"
                                for error in validation_errors[:5]
                            ),
                        },
                    },
                )
            return self._denial(
                safe_action_id,
                "DENY_INVALID_PROPOSAL",
                "Proposal failed strict schema validation.",
                self.policy.policy_hash,
            )

        with self.store.transaction() as conn:
            self.audit.append(conn, self._event("ACTION_PROPOSED", action))
            self.store.create_session(conn, action.session_id, action.actor_id, action.agent_id)
            session = conn.execute(
                "SELECT actor_id,agent_id FROM workflow_sessions WHERE session_id=?",
                (action.session_id,),
            ).fetchone()
            failure = self._authorize(conn, action, session)
            if failure:
                code, explanation = failure
                decision = self._decision(action.action_id, DecisionStatus.DENY, code, explanation)
                self._record_decision(conn, action, decision)
                return {"decision": decision, "result": None, "execution_error": None}

            decision = self._decision(
                action.action_id,
                DecisionStatus.ALLOW,
                f"ALLOW_{action.action_type.value}",
                f"Trusted policy permits {action.action_type.value.lower()} for this identity, resource, and purpose.",
            )
            self._record_decision(conn, action, decision)
            self.audit.append(conn, self._event("TOOL_EXECUTION_STARTED", action, decision))
            try:
                result = self._execute(conn, action)
            except Exception as exc:
                self.audit.append(
                    conn,
                    {
                        **self._event("TOOL_EXECUTION_FAILED", action, decision),
                        "metadata": {"error_type": type(exc).__name__},
                    },
                )
                return {
                    "decision": decision,
                    "result": None,
                    "execution_error": f"Protected operation failed ({type(exc).__name__}); no success was recorded.",
                }
            self.audit.append(conn, self._event("TOOL_EXECUTION_SUCCEEDED", action, decision))
            return {"decision": decision, "result": result, "execution_error": None}

    def _authorize(self, conn: sqlite3.Connection, action: ActionProposal, session) -> tuple[str, str] | None:
        if session["actor_id"] != action.actor_id or session["agent_id"] != action.agent_id:
            return "DENY_SESSION_IDENTITY_MISMATCH", "This workflow session is bound to different identities."
        resource_ids = (action.resource_id,)
        if action.action_type is ActionType.SAVE:
            resource_ids = tuple(dict.fromkeys((action.resource_id, *action.source_ids, *self.store.sources_for_session(conn, action.session_id))))
        for resource_id in resource_ids:
            artifact = self.store.get_artifact(conn, resource_id)
            if artifact is None:
                return "DENY_RESOURCE_NOT_FOUND", "The requested resource is not present in trusted storage."
            if not self.policy.permits_identity(action.actor_id, action.action_type, resource_id, action.purpose):
                return "DENY_USER_PERMISSION", "The delegated user is not authorized for this operation or resource."
            if not self.policy.permits_agent(action.agent_id, action.action_type, resource_id):
                return "DENY_AGENT_PERMISSION", "The agent does not have this operation or resource permission."

        if action.action_type is ActionType.SAVE:
            known_reads = set(self.store.sources_for_session(conn, action.session_id))
            declared = set(action.source_ids) | {action.resource_id}
            if not declared.issubset(known_reads):
                return "DENY_UNREAD_SOURCE", "Every derivation source must have been read in this workflow."
            if not action.source_ids and action.resource_id not in known_reads:
                return "DENY_UNREAD_SOURCE", "A report cannot be saved without a tracked source."

        if action.action_type is ActionType.DELIVER:
            artifact = self.store.get_artifact(conn, action.resource_id)
            recipient = self.policy.recipient(action.recipient_id or "")
            if recipient is None:
                return "DENY_RECIPIENT_UNKNOWN", "The recipient is not registered in trusted policy."
            if action.purpose not in recipient.purposes or not resource_matches(recipient.resources, action.resource_id):
                return "DENY_RECIPIENT_SCOPE", "The recipient is not authorized for this purpose or resource."
            effective = self.provenance.effective_label(conn, action.resource_id)
            if not can_flow_to(effective, recipient.clearance):
                return "DENY_INSUFFICIENT_CLEARANCE", f"{effective.value} exceeds the recipient's {recipient.clearance.value} clearance."
        return None

    def _execute(self, conn: sqlite3.Connection, action: ActionProposal):
        if action.action_type is ActionType.READ:
            return self.tools.read_document(conn, action.session_id, action.resource_id)
        if action.action_type is ActionType.SAVE:
            source_ids = tuple(
                dict.fromkeys(
                    (action.resource_id, *action.source_ids, *self.store.sources_for_session(conn, action.session_id))
                )
            )
            saved = self.tools.save_report(
                conn,
                session_id=action.session_id,
                actor_id=action.actor_id,
                source_ids=source_ids,
                content=action.content or "",
            )
            self.audit.append(
                conn,
                {
                    **self._event("ARTIFACT_SAVED", action),
                    "resource_id": saved.artifact_id,
                    "metadata": {"label": saved.label.value, "source_count": str(len(source_ids))},
                },
            )
            return saved
        if action.action_type is ActionType.DELIVER:
            artifact = self.store.get_artifact(conn, action.resource_id)
            if artifact is None:
                raise StorageError("Deliverable disappeared during execution")
            effective_label = self.provenance.effective_label(conn, artifact.artifact_id)
            message = self.tools.deliver(
                conn,
                recipient_id=action.recipient_id or "",
                artifact_id=artifact.artifact_id,
                label=effective_label,
            )
            self.audit.append(
                conn,
                {
                    **self._event("ARTIFACT_DELIVERED", action),
                    "metadata": {"recipient_id": action.recipient_id or "", "label": effective_label.value},
                },
            )
            return message
        raise ValueError(f"Unsupported action type: {action.action_type}")

    def declassify(self, actor_id: str, artifact_id: str, target: SecurityLabel, reason: str) -> dict:
        if not reason.strip() or len(reason) > 500:
            raise ValueError("A concise declassification reason is required")
        with self.store.transaction() as conn:
            artifact = self.store.get_artifact(conn, artifact_id)
            if artifact is None:
                raise StorageError("Cannot declassify an unknown artifact")
            if not self.policy.can_declassify(actor_id, artifact.label, target):
                self.audit.append(
                    conn,
                    {
                        "event_type": "CLASSIFICATION_CHANGE_DENIED",
                        "actor_id": actor_id,
                        "resource_id": artifact_id,
                        "status": "DENY",
                        "reason_code": "DENY_UNAUTHORIZED_DECLASSIFICATION",
                        "policy_hash": self.policy.policy_hash,
                    },
                )
                return {"allowed": False, "reason_code": "DENY_UNAUTHORIZED_DECLASSIFICATION"}
            if label_rank(target) >= label_rank(artifact.label):
                return {"allowed": False, "reason_code": "DENY_NOT_A_DOWNGRADE"}
            changed_at = datetime.now(timezone.utc).isoformat()
            conn.execute("UPDATE artifacts SET label=?, version=version+1 WHERE artifact_id=?", (target.value, artifact_id))
            conn.execute(
                """INSERT INTO classification_history(change_id,artifact_id,old_label,new_label,actor_id,reason,policy_hash,changed_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (str(uuid4()), artifact_id, artifact.label.value, target.value, actor_id, reason.strip(), self.policy.policy_hash, changed_at),
            )
            self.audit.append(
                conn,
                {
                    "event_type": "CLASSIFICATION_CHANGED",
                    "actor_id": actor_id,
                    "resource_id": artifact_id,
                    "status": "ALLOW",
                    "reason_code": "ALLOW_AUTHORIZED_DECLASSIFICATION",
                    "policy_hash": self.policy.policy_hash,
                    "timestamp": changed_at,
                    "metadata": {"old_label": artifact.label.value, "new_label": target.value, "reason": reason.strip()},
                },
            )
            return {"allowed": True, "old_label": artifact.label, "new_label": target}

    def resume(self, session_id: str) -> dict:
        result = self.store.reload_session(session_id)
        with self.store.transaction() as conn:
            self.audit.append(
                conn,
                {
                    "event_type": "WORKFLOW_RESUMED",
                    "resource_id": session_id,
                    "policy_hash": self.policy.policy_hash,
                },
            )
        return result

    def reload_policy(self) -> dict:
        with self.store.transaction() as conn:
            try:
                new_hash = self.policy.reload()
            except PolicyError as exc:
                self.audit.append(
                    conn,
                    {
                        "event_type": "POLICY_RELOAD_FAILED",
                        "reason_code": "DENY_POLICY_UNAVAILABLE",
                        "policy_hash": self.policy.policy_hash,
                        "metadata": {"error_type": type(exc).__name__},
                    },
                )
                return {"loaded": False, "policy_hash": self.policy.policy_hash}
            self.audit.append(
                conn,
                {
                    "event_type": "POLICY_RELOADED",
                    "status": "ALLOW",
                    "reason_code": "POLICY_RELOAD_SUCCESS",
                    "policy_hash": new_hash,
                },
            )
            return {"loaded": True, "policy_hash": new_hash}

    def _decision(self, action_id: str, status: DecisionStatus, code: str, explanation: str) -> Decision:
        return Decision(
            action_id=action_id,
            status=status,
            reason_code=code,
            explanation=explanation,
            policy_hash=self.policy.policy_hash,
        )

    def _record_decision(self, conn: sqlite3.Connection, action: ActionProposal, decision: Decision) -> None:
        self.audit.append(
            conn,
            {
                **self._event("AUTHORIZATION_DECISION", action, decision),
                "decision_id": decision.decision_id,
                "explanation": decision.explanation,
            },
        )

    def _event(self, event_type: str, action: ActionProposal, decision: Decision | None = None) -> dict:
        return {
            "event_type": event_type,
            "action_id": action.action_id,
            "actor_id": action.actor_id,
            "agent_id": action.agent_id,
            "resource_id": action.resource_id,
            "recipient_id": action.recipient_id,
            "operation": action.action_type.value,
            "status": decision.status.value if decision else None,
            "reason_code": decision.reason_code if decision else None,
            "policy_hash": self.policy.policy_hash,
            "timestamp": action.timestamp.isoformat(),
            "metadata": {"session_id": action.session_id, "purpose": action.purpose},
        }

    @staticmethod
    def _safe_action_id(value) -> str:
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.@+-]{1,128}", value):
            return value
        return str(uuid4())

    @staticmethod
    def _denial(action_id: str, code: str, explanation: str, policy_hash: str) -> dict:
        return {
            "decision": Decision(
                action_id=action_id,
                status=DecisionStatus.DENY,
                reason_code=code,
                explanation=explanation,
                policy_hash=policy_hash,
            ),
            "result": None,
            "execution_error": None,
        }
