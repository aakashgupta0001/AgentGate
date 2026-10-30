from pathlib import Path

import pytest

from agentgate.gateway import Gateway
from agentgate.policy import PolicyEngine
from agentgate.store import Store
from data.seed_data import seed_demo_data

ROOT = Path(__file__).resolve().parents[1]


class ToolSpy:
    def __init__(self, real_tools):
        self.real = real_tools
        self.read_calls = []
        self.save_calls = []
        self.deliver_calls = []

    def read_document(self, *args, **kwargs):
        self.read_calls.append((args, kwargs))
        return self.real.read_document(*args, **kwargs)

    def save_report(self, *args, **kwargs):
        self.save_calls.append((args, kwargs))
        return self.real.save_report(*args, **kwargs)

    def deliver(self, *args, **kwargs):
        self.deliver_calls.append((args, kwargs))
        return self.real.deliver(*args, **kwargs)


@pytest.fixture
def system(tmp_path):
    store = Store(tmp_path / "test.sqlite3")
    seed_demo_data(store)
    policy = PolicyEngine(ROOT / "policy" / "policy.yaml")
    gateway = Gateway(store, policy)
    spy = ToolSpy(gateway.tools)
    gateway.tools = spy
    return store, policy, gateway, spy
