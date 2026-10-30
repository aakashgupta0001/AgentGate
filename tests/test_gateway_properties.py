"""Property-based tests over the whole gateway, not individual helpers.

Each example runs a randomly generated hospital workflow (reads, an optional
report, an optional delivery) against a fresh database and then asserts the
security invariants that must hold no matter what the agent proposed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from agentgate.gateway import Gateway
from agentgate.labels import can_flow_to, max_label
from agentgate.models import ActionProposal, ActionType, DecisionStatus
from agentgate.policy import PolicyEngine
from agentgate.provenance import Provenance
from agentgate.store import Store
from data.seed_data import seed_demo_data

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "policy.yaml"

# Registered identities plus one unknown actor and one holding no permissions.
ACTORS = ("doctor_001", "billing_001", "privacy_001", "attacker_001", "ghost_001")
# Seeded artifacts plus one that does not exist.
RESOURCES = ("PUBLIC-0001", "INTERNAL-0001", "BILL-0001", "LAB-0001", "REPORT-0001", "MISSING-0001")
# Registered recipients plus one trusted policy does not know.
RECIPIENTS = ("doctor_inbox", "billing_inbox", "external_email", "unregistered_inbox")
# Legitimate purposes plus one an attacker might invent.
PURPOSES = (
    "treatment",
    "care_summary",
    "billing",
    "public_information",
    "patient_communication",
    "privacy_review",
    "exfiltration",
)


class CountingTools:
    """Wraps the real tools so a blocked action can be proven never to reach them."""

    def __init__(self, real):
        self.real = real
        self.calls = 0

    def read_document(self, *args, **kwargs):
        self.calls += 1
        return self.real.read_document(*args, **kwargs)

    def save_report(self, *args, **kwargs):
        self.calls += 1
        return self.real.save_report(*args, **kwargs)

    def deliver(self, *args, **kwargs):
        self.calls += 1
        return self.real.deliver(*args, **kwargs)


@pytest.fixture(scope="module")
def seeded_template(tmp_path_factory) -> Path:
    """Seed one database once; each example copies it so examples stay isolated and fast."""
    template = tmp_path_factory.mktemp("template") / "seeded.sqlite3"
    seed_demo_data(Store(template))
    return template


def build_system(seeded_template: Path, workspace: Path):
    database = workspace / "case.sqlite3"
    shutil.copyfile(seeded_template, database)
    store = Store(database)
    policy = PolicyEngine(POLICY_PATH)
    gateway = Gateway(store, policy)
    gateway.tools = CountingTools(gateway.tools)
    return store, policy, gateway, gateway.tools


def submit(gateway, tools, *, session, actor, action, resource, purpose, recipient=None, content=None):
    """Run one action and assert the universal rule: a denial never reaches a tool."""
    before = tools.calls
    outcome = gateway.decide_and_execute(
        ActionProposal(
            session_id=session,
            actor_id=actor,
            agent_id="agent_001",
            action_type=ActionType(action),
            resource_id=resource,
            recipient_id=recipient,
            purpose=purpose,
            content=content,
        )
    )
    if outcome["decision"].status is DecisionStatus.DENY:
        assert tools.calls == before, "a denied action still invoked a protected tool"
    return outcome


workflows = st.fixed_dictionaries(
    {
        "actor": st.sampled_from(ACTORS),
        "reads": st.lists(st.sampled_from(RESOURCES), max_size=3),
        "read_purpose": st.sampled_from(PURPOSES),
        "save": st.one_of(st.none(), st.tuples(st.sampled_from(RESOURCES), st.sampled_from(PURPOSES))),
        "deliver": st.one_of(
            st.none(),
            st.tuples(st.sampled_from(RESOURCES), st.sampled_from(RECIPIENTS), st.sampled_from(PURPOSES)),
        ),
        "deliver_saved_report": st.booleans(),
    }
)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(workflow=workflows)
def test_no_delivery_ever_exceeds_recipient_clearance(workflow, seeded_template, tmp_path_factory):
    """The invariant that matters: patient data never reaches a recipient without clearance.

    Whatever sequence of actions the agent proposes, every message that ends up in
    the mock inbox must have gone to a policy-registered recipient whose clearance
    dominates the delivered artifact's effective, provenance-aware label.
    """
    store, policy, gateway, tools = build_system(seeded_template, tmp_path_factory.mktemp("case"))
    session = "prop-session"

    for resource in workflow["reads"]:
        submit(
            gateway,
            tools,
            session=session,
            actor=workflow["actor"],
            action="READ",
            resource=resource,
            purpose=workflow["read_purpose"],
        )

    saved_report_id = None
    if workflow["save"] is not None:
        resource, purpose = workflow["save"]
        outcome = submit(
            gateway,
            tools,
            session=session,
            actor=workflow["actor"],
            action="SAVE",
            resource=resource,
            purpose=purpose,
            content="Synthetic generated report body.",
        )
        if outcome["decision"].status is DecisionStatus.ALLOW and outcome["result"] is not None:
            saved_report_id = outcome["result"].artifact_id

    if workflow["deliver"] is not None:
        resource, recipient, purpose = workflow["deliver"]
        if workflow["deliver_saved_report"] and saved_report_id is not None:
            resource = saved_report_id
        submit(
            gateway,
            tools,
            session=session,
            actor=workflow["actor"],
            action="DELIVER",
            resource=resource,
            purpose=purpose,
            recipient=recipient,
        )

    provenance = Provenance(store)
    with store.transaction(immediate=False) as conn:
        for message in store.inbox(conn):
            rule = policy.recipient(message["recipient_id"])
            assert rule is not None, "delivered to a recipient trusted policy does not register"
            effective = provenance.effective_label(conn, message["artifact_id"])
            assert can_flow_to(effective, rule.clearance), (
                "an artifact labelled "
                + effective.value
                + " reached a recipient holding only "
                + rule.clearance.value
                + " clearance"
            )
            assert message["label"] == effective.value, "recorded delivery label disagrees with provenance"
        assert gateway.audit.verify(conn)["valid"], "audit chain broken by a generated workflow"


@settings(max_examples=120, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(reads=st.lists(st.sampled_from(RESOURCES), min_size=1, max_size=4), purpose=st.sampled_from(PURPOSES))
def test_saved_report_always_inherits_most_restrictive_source_label(
    reads, purpose, seeded_template, tmp_path_factory
):
    """A derived report can never be less restricted than anything it was derived from."""
    store, _, gateway, tools = build_system(seeded_template, tmp_path_factory.mktemp("case"))
    session = "prop-save"
    actor = "privacy_001"  # broadest rights, so saves are actually reached

    for resource in reads:
        submit(gateway, tools, session=session, actor=actor, action="READ", resource=resource, purpose=purpose)

    outcome = submit(
        gateway,
        tools,
        session=session,
        actor=actor,
        action="SAVE",
        resource=reads[0],
        purpose=purpose,
        content="Derived synthetic summary.",
    )
    if outcome["decision"].status is not DecisionStatus.ALLOW or outcome["result"] is None:
        return

    report = outcome["result"]
    provenance = Provenance(store)
    with store.transaction(immediate=False) as conn:
        source_labels = [provenance.effective_label(conn, source_id) for source_id in report.source_ids]
        assert report.label is max_label(source_labels), "report label is below its most restrictive source"
        assert provenance.effective_label(conn, report.artifact_id) is max_label(source_labels)


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    actor=st.sampled_from(ACTORS),
    resource=st.sampled_from(RESOURCES),
    recipient=st.sampled_from(RECIPIENTS),
    purpose=st.sampled_from(PURPOSES),
)
def test_delivery_without_a_prior_read_is_still_fully_authorized(
    actor, resource, recipient, purpose, seeded_template, tmp_path_factory
):
    """A delivery attempted with no prior read is authorized like any other, never waved through."""
    store, policy, gateway, tools = build_system(seeded_template, tmp_path_factory.mktemp("case"))
    outcome = submit(
        gateway,
        tools,
        session="prop-deliver",
        actor=actor,
        action="DELIVER",
        resource=resource,
        purpose=purpose,
        recipient=recipient,
    )

    with store.transaction(immediate=False) as conn:
        if outcome["decision"].status is DecisionStatus.DENY:
            assert store.inbox(conn) == [], "a denied delivery left a message in the inbox"
        else:
            rule = policy.recipient(recipient)
            assert rule is not None
            effective = Provenance(store).effective_label(conn, resource)
            assert can_flow_to(effective, rule.clearance)
        assert gateway.audit.verify(conn)["valid"]
