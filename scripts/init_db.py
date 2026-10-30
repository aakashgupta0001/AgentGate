from agentgate.config import DB_PATH
from agentgate.store import Store


if __name__ == "__main__":
    Store(DB_PATH)
    print(f"Initialized AGENTGATE database at {DB_PATH}")
