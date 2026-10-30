from agentgate.audit import AuditLog
from agentgate.config import DB_PATH
from agentgate.store import Store


if __name__ == "__main__":
    store = Store(DB_PATH)
    with store.transaction(immediate=False) as conn:
        result = AuditLog().verify(conn)
    print(result)
    raise SystemExit(0 if result["valid"] else 1)
