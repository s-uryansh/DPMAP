import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


BACKEND_ROOT = Path(__file__).parents[2]
EXPECTED_TABLES = {
    "audit_events",
    "auth_sessions",
    "remediation_items",
    "scan_batches",
    "scan_inventory_items",
    "scan_jobs",
    "scan_reports",
    "users",
}
FORBIDDEN_COLUMNS = {
    "credential",
    "credentials",
    "database_password",
    "excerpt",
    "matched_value",
    "password",
    "sample",
    "source_value",
    "value_hash",
}


def _alembic_config(database_url: str) -> Config:
    config = Config(BACKEND_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _expect_rejected(engine, statement, parameters) -> None:
    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(statement, parameters)


def test_metadata_migration_contract() -> None:
    database_url = os.getenv("TEST_APP_DB_URL")
    if not database_url:
        pytest.skip("TEST_APP_DB_URL is required for PostgreSQL migration tests")

    config = _alembic_config(database_url)
    engine = create_engine(database_url)
    command.downgrade(config, "base")

    try:
        command.upgrade(config, "head")
        inspector = inspect(engine)
        assert EXPECTED_TABLES <= set(inspector.get_table_names())
        for table_name in EXPECTED_TABLES:
            column_names = {
                column["name"] for column in inspector.get_columns(table_name)
            }
            assert not column_names & FORBIDDEN_COLUMNS

        user_id, batch_id = uuid4(), uuid4()
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO users (id, email, role, password_hash) "
                    "VALUES (:id, 'admin@example.test', 'admin', 'test-hash')"
                ),
                {"id": user_id},
            )
            connection.execute(
                text(
                    "INSERT INTO scan_batches (id, label, created_by) "
                    "VALUES (:id, 'test batch', :user_id)"
                ),
                {"id": batch_id, "user_id": user_id},
            )

        insert_job = text(
            "INSERT INTO scan_jobs "
            "(id, batch_id, target_name, target_type, target_engine, "
            "target_display, target_fingerprint, status, progress_percent) "
            "VALUES (:id, :batch_id, 'target', 'database', 'postgresql', "
            "'db.example.test/example', :fingerprint, :status, :progress)"
        )
        base_job = {
            "batch_id": batch_id,
            "fingerprint": "a" * 64,
            "progress": 0,
            "status": "pending",
        }
        _expect_rejected(
            engine, insert_job, base_job | {"id": uuid4(), "status": "bad"}
        )
        _expect_rejected(
            engine, insert_job, base_job | {"id": uuid4(), "progress": 101}
        )
        _expect_rejected(
            engine, insert_job, base_job | {"id": uuid4(), "status": "completed"}
        )

        first_job_id = uuid4()
        with engine.begin() as connection:
            connection.execute(insert_job, base_job | {"id": first_job_id})
        _expect_rejected(engine, insert_job, base_job | {"id": uuid4()})

        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE scan_jobs SET status = 'completed', "
                    "progress_percent = 100, "
                    "finished_at = now() WHERE id = :id"
                ),
                {"id": first_job_id},
            )
            connection.execute(insert_job, base_job | {"id": uuid4()})

            inventory_id = uuid4()
            connection.execute(
                text(
                    "INSERT INTO scan_inventory_items "
                    "(id, job_id, location_kind, location_locator, pii_type, "
                    "match_count, units_with_pii, units_scanned, bytes_scanned, "
                    "confidence_band, detector_version, coverage_status) VALUES "
                    "(:id, :job_id, 'table', 'public.people', 'email', 1, 1, "
                    "1, 10, 'high', '1.0', 'complete')"
                ),
                {"id": inventory_id, "job_id": first_job_id},
            )
            connection.execute(
                text(
                    "INSERT INTO remediation_items "
                    "(id, job_id, inventory_item_id, rule_id, rule_version, "
                    "risk_score, risk_band, evidence_state, control_state, "
                    "recommended_control, suggested_owner) VALUES "
                    "(:id, :job_id, :inventory_id, 'retention', '1.0', 2, "
                    "'amber', 'unknown', 'unknown', 'Review retention', 'IT')"
                ),
                {"id": uuid4(), "job_id": first_job_id, "inventory_id": inventory_id},
            )
            connection.execute(
                text(
                    "INSERT INTO scan_reports "
                    "(id, job_id, report_schema_version) VALUES (:id, :job_id, '1.0')"
                ),
                {"id": uuid4(), "job_id": first_job_id},
            )
            connection.execute(
                text("DELETE FROM scan_jobs WHERE id = :id"), {"id": first_job_id}
            )
            for table_name in (
                "scan_inventory_items",
                "remediation_items",
                "scan_reports",
            ):
                remaining = connection.scalar(
                    text(f"SELECT count(*) FROM {table_name}")
                )
                assert remaining == 0
    finally:
        command.downgrade(config, "base")
        assert not EXPECTED_TABLES & set(inspect(engine).get_table_names())
        engine.dispose()
