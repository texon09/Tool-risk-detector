"""Run the SQLite audit schema migration explicitly from ``backend/``."""

from app.audit.store import AuditStore


def main() -> None:
    store = AuditStore()
    result = store.verify_chain()
    if not result["valid"]:
        raise SystemExit(f"Audit migration completed but verification failed: {result}")
    print(f"Audit schema ready at {store.db_path}; {result['reason']}")


if __name__ == "__main__":
    main()
