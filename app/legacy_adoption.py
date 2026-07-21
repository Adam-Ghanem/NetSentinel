"""Read-only validation for adopting pre-Alembic NetSentinel databases."""

from sqlalchemy import create_engine, inspect, text

from app.database import Base
from app.schema import SCHEMA_VERSION_TABLE


def inspect_legacy_database(database_url):
    """Return a sanitized, deterministic adoption-readiness report.

    The validator never creates, alters, or stamps schema. Operators may only
    proceed to an explicit Alembic stamp after this report is ``ready``.
    """
    engine = create_engine(database_url, pool_pre_ping=True)
    expected_tables = set(Base.metadata.tables)
    expected_tables.discard(SCHEMA_VERSION_TABLE)
    report = {
        "status": "blocked",
        "connectivity": "unknown",
        "schema_version": "absent",
        "missing_tables": [],
        "unexpected_tables": [],
        "column_mismatches": {},
    }

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            report["connectivity"] = "ok"

        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())
        application_tables = existing_tables - {"alembic_version", SCHEMA_VERSION_TABLE}

        report["missing_tables"] = sorted(expected_tables - application_tables)
        report["unexpected_tables"] = sorted(application_tables - expected_tables)

        mismatches = {}
        for table_name in sorted(expected_tables & application_tables):
            expected_columns = set(Base.metadata.tables[table_name].columns.keys())
            existing_columns = {
                column["name"] for column in inspector.get_columns(table_name)
            }
            missing_columns = sorted(expected_columns - existing_columns)
            unexpected_columns = sorted(existing_columns - expected_columns)
            if missing_columns or unexpected_columns:
                mismatches[table_name] = {
                    "missing": missing_columns,
                    "unexpected": unexpected_columns,
                }
        report["column_mismatches"] = mismatches

        if SCHEMA_VERSION_TABLE in existing_tables or "alembic_version" in existing_tables:
            report["schema_version"] = "already_managed"
            report["reason"] = "database already contains migration metadata"
        elif report["missing_tables"]:
            report["reason"] = "required application tables are missing"
        elif mismatches:
            report["reason"] = "application table columns do not match current models"
        else:
            report["status"] = "ready"
            report["reason"] = "legacy schema matches current application metadata"
    except Exception as exc:
        report.update(
            {
                "status": "unhealthy",
                "connectivity": "failed",
                "error": type(exc).__name__,
                "reason": "database inspection failed",
            }
        )
    finally:
        engine.dispose()

    return report
