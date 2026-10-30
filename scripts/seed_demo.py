from agentgate.config import DB_PATH
from agentgate.store import Store
from data.seed_data import seed_demo_data


if __name__ == "__main__":
    store = Store(DB_PATH)
    seed_demo_data(store)
    print(f"Seeded synthetic demo artifacts in {DB_PATH}")
