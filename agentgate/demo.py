from agentgate.agent import propose_action
from agentgate.config import DB_PATH, POLICY_PATH
from agentgate.gateway import Gateway
from agentgate.policy import PolicyEngine
from agentgate.store import Store
from data.seed_data import seed_demo_data


def main() -> None:
    store = Store(DB_PATH)
    seed_demo_data(store)
    gateway = Gateway(store, PolicyEngine(POLICY_PATH))
    for action_type, recipient, purpose in (
        ("READ", None, "treatment"),
        ("DELIVER", "external_email", "public_information"),
    ):
        proposal = propose_action(
            "SIMULATION — scripted compromised agent" if recipient else "Read synthetic lab",
            {
                "session_id": "demo-session",
                "actor_id": "doctor_001",
                "agent_id": "agent_001",
                "action_type": action_type,
                "resource_id": "LAB-0001",
                "recipient_id": recipient,
                "purpose": purpose,
            },
        )
        result = gateway.decide_and_execute(proposal)
        print(
            f"{result['decision'].status.value}: {result['decision'].reason_code} — "
            f"{result['decision'].explanation}"
        )


if __name__ == "__main__":
    main()
