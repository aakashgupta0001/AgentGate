from datetime import datetime, timezone

import pytest
from hypothesis import given, strategies as st
from pydantic import ValidationError

from agentgate.audit import AuditLog
from agentgate.agent import propose_action
from agentgate.models import ActionProposal, ActionType, DecisionStatus, SecurityLabel
from agentgate.provenance import Provenance
from agentgate.labels import label_rank, max_label
from agentgate.store import Store


def proposal(session, action="READ", resource="LAB-0001", actor="doctor_001", recipient=None, purpose="treatment", **kwargs):
    context = {
        "session_id": session,
        "actor_id": actor,
        "agent_id": "agent_001",
        "action_type": action,
        "resource_id": resource,
        "recipient_id": recipient,
        "purpose": purpose,
        **kwargs,
    }
    return propose_action("synthetic request", context)


def test_strict_proposal_rejects_authorization_claim():
    with pytest.raises(ValidationError):
        ActionProposal.model_validate(
            {
                "session_id": "test",
                "actor_id": "doctor_001",
                "agent_id": "agent_001",
                "action_type": "READ",
                "resource_id": "LAB-0001",
                "purpose": "treatment",
                "authorized": True,
            }
        )


def test_aware_timestamp_required():
    with pytest.raises(ValidationError):
        ActionProposal(
            session_id="test",
            actor_id="doctor_001",
            agent_id="agent_001",
            action_type=ActionType.READ,
            resource_id="LAB-0001",
            purpose="treatment",
            timestamp=datetime(2026, 1, 1),
        )


def test_authorized_read_executes_once(system):
    _, _, gateway, spy = system
    result = gateway.decide_and_execute(proposal("read-ok"))
    assert result["decision"].status is DecisionStatus.ALLOW
    assert len(spy.read_calls) == 1
    assert result["result"].label is SecurityLabel.PATIENT_RESTRICTED


def test_unauthorized_read_never_executes(system):
    _, _, gateway, spy = system
    result = gateway.decide_and_execute(proposal("read-denied", actor="attacker_001"))
    assert result["decision"].status is DecisionStatus.DENY
    assert not spy.read_calls


def test_prompt_injected_delivery_never_calls_tool_or_inserts_inbox(system):
    store, _, gateway, spy = system
    result = gateway.decide_and_execute(
        proposal("attack", action="DELIVER", resource="LAB-0001", recipient="external_email", purpose="public_information")
    )
    assert result["decision"].status is DecisionStatus.DENY
    assert result["decision"].reason_code == "DENY_INSUFFICIENT_CLEARANCE"
    assert not spy.deliver_calls
    with store.transaction(immediate=False) as conn:
        assert store.inbox(conn) == []
        assert gateway.audit.verify(conn)["valid"]


def test_report_inherits_all_read_sources_and_persists(system):
    store, _, gateway, spy = system
    session = "save-report"
    assert gateway.decide_and_execute(proposal(session))["decision"].status is DecisionStatus.ALLOW
    result = gateway.decide_and_execute(
        proposal(session, action="SAVE", resource="LAB-0001", purpose="care_summary", content="Short summary.")
    )
    assert result["decision"].status is DecisionStatus.ALLOW
    report = result["result"]
    assert report.label is SecurityLabel.PATIENT_RESTRICTED
    assert report.source_ids == ("LAB-0001",)
    assert len(spy.save_calls) == 1
    with store.transaction(immediate=False) as conn:
        restored = store.get_artifact(conn, report.artifact_id)
        assert restored and restored.label is SecurityLabel.PATIENT_RESTRICTED
        assert Provenance(store).effective_label(conn, report.artifact_id) is SecurityLabel.PATIENT_RESTRICTED


def test_multiple_source_report_uses_most_restrictive_label(system):
    _, _, gateway, _ = system
    session = "multi-source"
    assert gateway.decide_and_execute(proposal(session, resource="PUBLIC-0001", purpose="public_information"))["decision"].status is DecisionStatus.ALLOW
    assert gateway.decide_and_execute(proposal(session))["decision"].status is DecisionStatus.ALLOW
    result = gateway.decide_and_execute(
        proposal(
            session,
            action="SAVE",
            resource="LAB-0001",
            purpose="care_summary",
            source_ids=("PUBLIC-0001",),
            content="Combined synthetic source report.",
        )
    )
    assert result["decision"].status is DecisionStatus.ALLOW
    assert result["result"].label is SecurityLabel.PATIENT_RESTRICTED
    assert set(result["result"].source_ids) == {"LAB-0001", "PUBLIC-0001"}


def test_save_without_read_is_denied_without_tool_execution(system):
    _, _, gateway, spy = system
    result = gateway.decide_and_execute(
        proposal("save-unread", action="SAVE", resource="LAB-0001", purpose="care_summary", content="attempted")
    )
    assert result["decision"].status is DecisionStatus.DENY
    assert not spy.save_calls


def test_unknown_recipient_denied(system):
    _, _, gateway, spy = system
    result = gateway.decide_and_execute(
        proposal("unknown-recipient", action="DELIVER", resource="REPORT-0001", recipient="missing", purpose="patient_communication")
    )
    assert result["decision"].reason_code == "DENY_RECIPIENT_UNKNOWN"
    assert not spy.deliver_calls


def test_agent_and_user_permissions_are_intersected(system):
    _, _, gateway, spy = system
    result = gateway.decide_and_execute(
        proposal("billing-lab", actor="billing_001", resource="LAB-0001", purpose="billing")
    )
    assert result["decision"].status is DecisionStatus.DENY
    assert not spy.read_calls


def test_doctor_cannot_declassify_and_privacy_officer_change_is_audited(system):
    store, _, gateway, _ = system
    denied = gateway.declassify("doctor_001", "LAB-0001", SecurityLabel.PUBLIC, "not authorized")
    assert not denied["allowed"]
    allowed = gateway.declassify("privacy_001", "LAB-0001", SecurityLabel.CONFIDENTIAL, "approved synthetic demo review")
    assert allowed["allowed"]
    with store.transaction(immediate=False) as conn:
        assert store.get_artifact(conn, "LAB-0001").label is SecurityLabel.CONFIDENTIAL
        history = conn.execute("SELECT old_label,new_label,actor_id FROM classification_history").fetchone()
        assert tuple(history) == ("PATIENT_RESTRICTED", "CONFIDENTIAL", "privacy_001")


def test_lowering_derived_artifact_does_not_launder_ancestor(system):
    _, _, gateway, spy = system
    change = gateway.declassify("privacy_001", "REPORT-0001", SecurityLabel.PUBLIC, "synthetic declassification exercise")
    assert change["allowed"]
    result = gateway.decide_and_execute(
        proposal(
            "laundering-attempt",
            action="DELIVER",
            resource="REPORT-0001",
            recipient="external_email",
            purpose="public_information",
        )
    )
    assert result["decision"].status is DecisionStatus.DENY
    assert result["decision"].reason_code == "DENY_INSUFFICIENT_CLEARANCE"
    assert not spy.deliver_calls


def test_session_restores_reads_and_artifacts_after_fresh_store(system, tmp_path):
    store, _, gateway, _ = system
    session = "resume-test"
    gateway.decide_and_execute(proposal(session))
    restored_store = Store(store.path)
    restored_gateway = type(gateway)(restored_store, gateway.policy)
    state = restored_gateway.resume(session)
    assert "LAB-0001" in state["reads"]
    assert any(item.artifact_id == "LAB-0001" for item in state["artifacts"])


def test_audit_detects_modified_payload(system):
    store, _, gateway, _ = system
    gateway.decide_and_execute(proposal("audit-change"))
    with store.transaction() as conn:
        conn.execute("UPDATE audit_events SET payload_json='{}' WHERE sequence=1")
    with store.transaction(immediate=False) as conn:
        assert not AuditLog().verify(conn)["valid"]


def test_audit_detects_truncated_chain_head(system):
    store, _, gateway, _ = system
    gateway.decide_and_execute(proposal("audit-truncate"))
    with store.transaction() as conn:
        conn.execute("DELETE FROM audit_events WHERE sequence=(SELECT MAX(sequence) FROM audit_events)")
    with store.transaction(immediate=False) as conn:
        result = AuditLog().verify(conn)
    assert not result["valid"]
    assert result["reason"] == "stored chain head mismatch"


def test_invalid_proposal_is_audited_and_rejected(system):
    store, _, gateway, spy = system
    result = gateway.decide_and_execute({"action_type": "READ", "authorized": True})
    assert result["decision"].status is DecisionStatus.DENY
    assert not spy.read_calls
    with store.transaction(immediate=False) as conn:
        event = conn.execute("SELECT payload_json FROM audit_events").fetchone()
        assert "PROPOSAL_REJECTED" in event["payload_json"]


def test_authorized_mock_delivery_is_persisted(system):
    store, _, gateway, spy = system
    result = gateway.decide_and_execute(
        proposal("delivery-ok", action="DELIVER", resource="REPORT-0001", recipient="doctor_inbox", purpose="patient_communication")
    )
    assert result["decision"].status is DecisionStatus.ALLOW
    assert len(spy.deliver_calls) == 1
    with store.transaction(immediate=False) as conn:
        assert len(store.inbox(conn)) == 1


def test_public_delivery_to_external_recipient_is_allowed(system):
    _, _, gateway, spy = system
    result = gateway.decide_and_execute(
        proposal("public-delivery", action="DELIVER", resource="PUBLIC-0001", recipient="external_email", purpose="public_information")
    )
    assert result["decision"].status is DecisionStatus.ALLOW
    assert len(spy.deliver_calls) == 1


def test_metrics_distinguish_decisions_and_deliveries(system):
    store, _, gateway, _ = system
    gateway.decide_and_execute(proposal("metric-allow"))
    gateway.decide_and_execute(
        proposal("metric-deny", action="DELIVER", resource="LAB-0001", recipient="external_email", purpose="public_information")
    )
    with store.transaction(immediate=False) as conn:
        metrics = store.metrics(conn)
    assert metrics["decisions"] == 2
    assert metrics["allowed"] == 1
    assert metrics["denied"] == 1
    assert metrics["deliveries"] == 0
    assert metrics["blocked_deliveries"] == 1


def test_failed_tool_is_audited_as_failure_not_success(system):
    store, _, gateway, spy = system

    def explode(*args, **kwargs):
        raise OSError("synthetic tool outage")

    spy.read_document = explode
    result = gateway.decide_and_execute(proposal("tool-fails"))
    assert result["decision"].status is DecisionStatus.ALLOW
    assert result["execution_error"]
    with store.transaction(immediate=False) as conn:
        kinds = [event["event_type"] for event in gateway.audit.events(conn)]
    assert "TOOL_EXECUTION_FAILED" in kinds
    assert "TOOL_EXECUTION_SUCCEEDED" not in kinds


def test_policy_reload_is_explicit_and_fails_closed(system, tmp_path):
    store, policy, gateway, _ = system
    old_hash = policy.policy_hash
    policy.path = tmp_path / "invalid-policy.yaml"
    policy.path.write_text("identities: [", encoding="utf-8")
    result = gateway.reload_policy()
    assert not result["loaded"]
    assert policy.policy_hash == old_hash
    with store.transaction(immediate=False) as conn:
        event_types = [event["event_type"] for event in gateway.audit.events(conn)]
    assert "POLICY_RELOAD_FAILED" in event_types


def test_empty_audit_chain_and_label_helpers(system):
    store, _, gateway, _ = system
    with store.transaction(immediate=False) as conn:
        assert gateway.audit.verify(conn)["valid"]
    assert label_rank(SecurityLabel.PUBLIC) == 0
    assert max_label([SecurityLabel.PUBLIC, SecurityLabel.CONFIDENTIAL]) is SecurityLabel.CONFIDENTIAL
    with pytest.raises(ValueError):
        max_label([])
    with pytest.raises(ValueError):
        label_rank("UNTRUSTED")


@given(st.sampled_from(list(SecurityLabel)), st.sampled_from(list(SecurityLabel)))
def test_label_ordering_allows_only_equal_or_lower_data_flow(source, clearance):
    from agentgate.labels import can_flow_to

    expected = list(SecurityLabel).index(source) <= list(SecurityLabel).index(clearance)
    assert can_flow_to(source, clearance) is expected
