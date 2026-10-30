import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def configured_path(name: str, default: str) -> Path:
    value = Path(os.getenv(name, default))
    return value if value.is_absolute() else ROOT / value


DB_PATH = configured_path("AGENTGATE_DB_PATH", "storage/agentgate.sqlite3")
POLICY_PATH = configured_path("AGENTGATE_POLICY_PATH", "policy/policy.yaml")
MODEL_MODE = os.getenv("AGENTGATE_MODEL_MODE", "simulation").lower()
