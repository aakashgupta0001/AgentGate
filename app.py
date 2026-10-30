from __future__ import annotations

import streamlit as st

from agentgate.agent import propose_action
from agentgate.config import DB_PATH, MODEL_MODE, POLICY_PATH
from agentgate.gateway import Gateway
from agentgate.models import ActionType, SecurityLabel
from agentgate.policy import PolicyEngine
from agentgate.provenance import Provenance
from agentgate.store import Store
from data.seed_data import seed_demo_data

st.set_page_config(page_title="AGENTGATE | Hospital AI Security", page_icon="🛡️", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: #f5f8fc; }
    [data-testid="stSidebar"] { background: #10243a; }
    [data-testid="stSidebar"] * { color: #eef5ff; }
    .hero { padding: 1.25rem 1.5rem; border-radius: 14px; color: white;
            background: linear-gradient(110deg,#10243a,#176b78); margin-bottom: 1rem; }
    .hero h1 { margin: 0; font-size: 2rem; }
    .hero p { margin: .35rem 0 0; opacity: .9; }
    .sim { border-left: 5px solid #e6a700; padding: .8rem 1rem; background: #fff7dc;
           color: #4a3900; border-radius: 6px; font-weight: 700; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def services() -> tuple[Store, PolicyEngine, Gateway]:
    store = Store(DB_PATH)
    seed_demo_data(store)
    policy = PolicyEngine(POLICY_PATH)
    return store, policy, Gateway(store, policy)


try:
    store, policy, gateway = services()
except Exception as exc:
    st.error(f"AGENTGATE startup failed closed: {type(exc).__name__}: {exc}")
    st.stop()

st.sidebar.markdown("## 🛡️ AGENTGATE")
st.sidebar.caption("Hospital AI security gateway")
st.sidebar.markdown("**Mode:** " + MODEL_MODE.upper())
if MODEL_MODE == "simulation":
    st.sidebar.warning("SIMULATION — SCRIPTED COMPROMISED AGENT")
actor_id = st.sidebar.selectbox(
    "Simulated user identity",
    ["doctor_001", "billing_001", "privacy_001", "attacker_001"],
    format_func=lambda value: f"{value} (SIMULATED)",
)
st.sidebar.caption(f"Agent identity: `agent_001` (simulated)")
session_id = f"dashboard-{actor_id}"
st.sidebar.caption(f"Workflow session: `{session_id}`")
st.sidebar.caption(f"Database: `{DB_PATH}`")
st.sidebar.success("Policy loaded")
st.sidebar.caption(f"SHA-256: `{policy.policy_hash}`")
if st.sidebar.button("Reload trusted policy"):
    reload_result = gateway.reload_policy()
    if reload_result["loaded"]:
        st.sidebar.success("Policy reloaded; hash updated.")
        st.rerun()
    st.sidebar.error("Policy reload failed closed; previous policy remains active.")
page = st.sidebar.radio(
    "Workspace",
    ["Overview", "Task runner", "Documents", "Decision feed", "Provenance", "Mock inbox", "Audit explorer", "Resume workflow", "Privacy officer"],
)

st.markdown(
    '<div class="hero"><h1>AGENTGATE</h1><p>The AI proposes. AGENTGATE decides. The tool executes only after authorization.</p></div>',
    unsafe_allow_html=True,
)


def perform(action_type: ActionType, resource_id: str, purpose: str, recipient_id: str | None = None, content: str | None = None):
    context = {
        "session_id": session_id,
        "actor_id": actor_id,
        "agent_id": "agent_001",
        "action_type": action_type,
        "resource_id": resource_id,
        "recipient_id": recipient_id,
        "purpose": purpose,
        "content": content,
        "source_ids": (resource_id,) if action_type is ActionType.SAVE else (),
    }
    try:
        proposal = propose_action("SIMULATION — demonstration task", context, mode=MODEL_MODE)
        outcome = gateway.decide_and_execute(proposal)
        decision = outcome["decision"]
        (st.success if decision.status.value == "ALLOW" else st.error)(
            f"{decision.status.value} · {decision.reason_code} · {decision.explanation}"
        )
        st.caption(f"Action `{decision.action_id}` · policy `{decision.policy_hash}`")
        if outcome["execution_error"]:
            st.error(outcome["execution_error"])
        elif outcome["result"] is not None:
            st.write("Tool result (from controlled local storage):")
            st.json(_json_result(outcome["result"]))
        return outcome
    except Exception as exc:
        st.error(f"Request could not be completed: {type(exc).__name__}: {exc}")
        return None


def _json_result(result):
    if hasattr(result, "model_dump"):
        return result.model_dump(mode="json")
    return result


if page == "Overview":
    metric_slots = st.columns(6)
    metric_titles = ("Artifacts", "Authorization decisions", "Allowed actions", "Denied actions", "Mock deliveries", "Blocked deliveries")
    metric_keys = ("artifacts", "decisions", "allowed", "denied", "deliveries", "blocked_deliveries")
    st.subheader("Security posture")
    left, right = st.columns(2)
    version_slot = left.empty()
    audit_slot = right.empty()
    st.info("All identities and patient records in this demonstration are synthetic. No real email is sent.")
    st.markdown('<div class="sim">SIMULATION — SCRIPTED COMPROMISED AGENT. The attack workflow is deterministic; it is not live model output.</div>', unsafe_allow_html=True)
    st.subheader("Quick demonstrations")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Run authorized doctor read"):
            perform(ActionType.READ, "LAB-0001", "treatment")
        if st.button("Summarize and save restricted report"):
            read = perform(ActionType.READ, "LAB-0001", "treatment")
            if read and read["decision"].status.value == "ALLOW":
                perform(ActionType.SAVE, "LAB-0001", "care_summary", content="Synthetic lab summary for clinician review.")
    with c2:
        if st.button("Simulate prompt-injected external delivery"):
            st.warning("The poisoned document instruction is untrusted input. The gateway still makes the decision.")
            perform(ActionType.DELIVER, "LAB-0001", "public_information", "external_email")
        if st.button("Deliver seeded report to treating doctor"):
            perform(ActionType.DELIVER, "REPORT-0001", "patient_communication", "doctor_inbox")
    with store.transaction(immediate=False) as conn:
        metrics = store.metrics(conn)
        audit_status = gateway.audit.verify(conn)
    for column, title, key in zip(metric_slots, metric_titles, metric_keys):
        column.metric(title, metrics[key])
    version_slot.metric("Policy version", policy.config.version)
    audit_slot.metric("Audit chain", "VERIFIED" if audit_status["valid"] else "BROKEN", help=audit_status["reason"])

elif page == "Task runner":
    st.subheader("Task runner")
    st.caption("Proposed action is shown separately from the result returned by the authorization gateway.")
    task = st.selectbox("Demonstration", ["Read synthetic lab report", "Save derived report", "Attempt external delivery", "Deliver to treating doctor"])
    if st.button("Propose and run through gateway", type="primary"):
        if task == "Read synthetic lab report":
            perform(ActionType.READ, "LAB-0001", "treatment")
        elif task == "Save derived report":
            with store.transaction(immediate=False) as conn:
                reads = store.sources_for_session(conn, session_id)
            if "LAB-0001" not in reads:
                st.info("Reading the source in this workflow first.")
                read = perform(ActionType.READ, "LAB-0001", "treatment")
                allowed = bool(read and read["decision"].status.value == "ALLOW")
            else:
                allowed = True
            if allowed:
                perform(ActionType.SAVE, "LAB-0001", "care_summary", content="Synthetic summary. Classification is derived by the gateway.")
        elif task == "Attempt external delivery":
            perform(ActionType.DELIVER, "LAB-0001", "public_information", "external_email")
        else:
            perform(ActionType.DELIVER, "REPORT-0001", "patient_communication", "doctor_inbox")

elif page == "Documents":
    st.subheader("Synthetic document explorer")
    with store.transaction(immediate=False) as conn:
        artifacts = store.list_artifacts(conn)
    selected_id = st.selectbox("Stored artifact", [item.artifact_id for item in artifacts])
    artifact = next(item for item in artifacts if item.artifact_id == selected_id)
    st.warning(f"Trusted stored label: {artifact.label.value}")
    st.caption("Document body is untrusted data and cannot change the trusted policy or label.")
    st.text_area("Synthetic content", artifact.content, height=180, disabled=True)
    st.write("Provenance sources:", ", ".join(artifact.source_ids) if artifact.source_ids else "None")
    if st.button("Request read through gateway"):
        perform(ActionType.READ, artifact.artifact_id, "treatment")

elif page == "Provenance":
    st.subheader("Artifact provenance")
    with store.transaction(immediate=False) as conn:
        st.graphviz_chart(Provenance(store).graph_dot(conn), use_container_width=True)
        artifacts = store.list_artifacts(conn)
    st.dataframe(
        [{"Artifact": item.artifact_id, "Type": item.artifact_type, "Trusted label": item.label.value, "Sources": ", ".join(item.source_ids)} for item in artifacts],
        use_container_width=True,
    )

elif page == "Decision feed":
    st.subheader("Security decision feed")
    with store.transaction(immediate=False) as conn:
        decisions = [
            event for event in gateway.audit.events(conn)
            if event.get("event_type") in {"AUTHORIZATION_DECISION", "PROPOSAL_REJECTED"}
        ]
    filters = st.columns(5)
    status_filter = filters[0].selectbox("Result", ["ALL", "ALLOW", "DENY"])
    operation_filter = filters[1].selectbox("Operation", ["ALL", "READ", "SAVE", "DELIVER"])
    actor_filter = filters[2].text_input("Identity contains")
    recipient_filter = filters[3].text_input("Recipient contains")
    resource_filter = filters[4].text_input("Resource contains")
    session_filter = st.text_input("Session contains")
    filtered = [
        event for event in decisions
        if (status_filter == "ALL" or event.get("status") == status_filter)
        and (operation_filter == "ALL" or event.get("operation") == operation_filter)
        and actor_filter.lower() in str(event.get("actor_id", "")).lower()
        and recipient_filter.lower() in str(event.get("recipient_id", "")).lower()
        and resource_filter.lower() in str(event.get("resource_id", "")).lower()
        and session_filter.lower() in str(event.get("metadata", {}).get("session_id", "")).lower()
    ]
    st.dataframe(filtered[::-1], use_container_width=True)
    st.caption("Attempted operations, authorization decisions, and successful mock deliveries are stored separately.")

elif page == "Mock inbox":
    st.subheader("Persisted mock inbox")
    with store.transaction(immediate=False) as conn:
        inbox = store.inbox(conn)
    if inbox:
        st.dataframe(inbox, use_container_width=True)
    else:
        st.info("No successful mock deliveries. Denied actions are intentionally not inserted here.")

elif page == "Audit explorer":
    st.subheader("Tamper-evident audit chain")
    with store.transaction(immediate=False) as conn:
        events = gateway.audit.events(conn)
        verification = gateway.audit.verify(conn)
    if st.button("Verify complete audit chain"):
        if verification["valid"]:
            st.success(f"Valid chain · {verification['checked']} events · head `{verification['head']}`")
        else:
            st.error(f"Chain verification failed after {verification['checked']} events: {verification['reason']}")
    st.dataframe(events, use_container_width=True)
    st.caption("The hash chain detects changes but is stored in the same writable database; it is not an immutable external audit service.")

elif page == "Resume workflow":
    st.subheader("Restore workflow from SQLite")
    with store.transaction(immediate=False) as conn:
        session_ids = [row["session_id"] for row in conn.execute("SELECT session_id FROM workflow_sessions ORDER BY created_at DESC")]
    if session_ids:
        selected_session = st.selectbox("Previous workflow", session_ids)
        if st.button("Resume selected workflow"):
            restored = gateway.resume(selected_session)
            st.success(f"Reloaded {len(restored['artifacts'])} artifacts and {len(restored['reads'])} recorded reads.")
            st.dataframe([{"artifact": a.artifact_id, "label": a.label.value, "sources": a.source_ids} for a in restored["artifacts"]])
            st.caption("Labels and source links above were reloaded from authoritative SQLite columns.")

elif page == "Privacy officer":
    st.subheader("Separate privacy-officer classification administration")
    st.warning("This operation is not exposed as an agent tool. Policy validation is performed by the gateway.")
    with store.transaction(immediate=False) as conn:
        artifacts = store.list_artifacts(conn)
    selected = st.selectbox("Artifact", [a.artifact_id for a in artifacts])
    target = st.selectbox("Target classification", list(SecurityLabel))
    reason = st.text_input("Reason for change")
    confirmed = st.checkbox("I confirm this authorized classification change")
    if st.button("Request declassification", disabled=not confirmed):
        try:
            outcome = gateway.declassify(actor_id, selected, target, reason)
            if outcome["allowed"]:
                st.success(f"Classification changed: {outcome['old_label'].value} → {outcome['new_label'].value}")
            else:
                st.error(f"Denied: {outcome['reason_code']}")
        except Exception as exc:
            st.error(f"Classification request failed: {type(exc).__name__}: {exc}")
