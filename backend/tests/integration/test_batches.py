import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import time
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from dpmap.api.routes import scans as scan_routes
from dpmap.core.security import encode_access_token, hash_password
from dpmap.db.models import (
    AuditEvent,
    AuthSession,
    ScanBatch,
    ScanInventoryItem,
    ScanJob,
    User,
)
from dpmap.jobs import coordinator
from dpmap.main import create_app
from asgi import request


BACKEND_ROOT = Path(__file__).parents[2]


def _alembic_config(database_url: str) -> Config:
    config = Config(BACKEND_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _setup(database_url: str, monkeypatch):
    config = _alembic_config(database_url)
    engine = create_engine(database_url)
    sessions = sessionmaker(engine, expire_on_commit=False)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    jwt_secret = secrets.token_urlsafe(48)
    monkeypatch.setenv("JWT_SECRET", jwt_secret)
    monkeypatch.setenv("APP_DB_URL", database_url)
    now = datetime.now(timezone.utc)
    user_id, jti = uuid4(), uuid4()
    with sessions() as database:
        database.add(
            User(
                id=user_id,
                email="batch-scanner@example.test",
                role="admin",
                password_hash=hash_password("batch-test-password"),
            )
        )
        database.flush()
        database.add(
            AuthSession(
                id=jti,
                user_id=user_id,
                expires_at=now + timedelta(minutes=15),
            )
        )
        database.commit()
    token = encode_access_token(
        user_id=user_id,
        jti=jti,
        secret=jwt_secret,
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
    )
    return config, engine, sessions, user_id, token


def _wait_for_batch(app, batch_id, token):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response = request(
            app, "GET", f"/api/v1/batches/{batch_id}/status", token=token
        )
        if response[1]["status"] in {
            "completed",
            "completed_with_failures",
            "failed",
            "cancelled",
        }:
            return response
        time.sleep(0.05)
    raise AssertionError("batch did not finish")


def test_mixed_batch_isolated_failure_and_stable_duplicate_conflict(
    tmp_path, monkeypatch
) -> None:
    database_url = os.getenv("TEST_APP_DB_URL")
    if not database_url:
        pytest.fail("TEST_APP_DB_URL is required for Task 9 verification")
    config, engine, sessions, _, token = _setup(database_url, monkeypatch)
    root = tmp_path / "batch-files"
    root.mkdir()
    pii_value = "batch.person@example.in"
    (root / "contacts.txt").write_text(pii_value, encoding="utf-8")
    password = secrets.token_urlsafe(32)
    monkeypatch.setenv("ALLOWED_SCAN_ROOTS", str(tmp_path))
    monkeypatch.setenv("ALLOWED_DB_HOSTS", "127.0.0.1")
    monkeypatch.setenv("ALLOW_INSECURE_TARGET_TLS", "true")
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA IF EXISTS batch_fixture CASCADE"))
        connection.execute(text("CREATE SCHEMA batch_fixture"))
        connection.execute(
            text("CREATE TABLE batch_fixture.contacts (email text)")
        )
        connection.execute(
            text("INSERT INTO batch_fixture.contacts VALUES (:value)"),
            {"value": pii_value},
        )

    app = create_app()
    payload = {
        "label": "Mixed target batch",
        "targets": [
            {
                "client_ref": "postgres-ok",
                "target_name": "Working PostgreSQL",
                "type": "database",
                "database": {
                    "engine": "postgresql",
                    "host": "127.0.0.1",
                    "port": 55432,
                    "database": "dpmap_test",
                    "username": "postgres",
                    "password": password,
                    "tls_mode": "disable",
                },
                "scope": {"schemas": ["batch_fixture"]},
                "detectors": ["email"],
                "governance_context": {"owner": "IT"},
                "control_evidence": {"retention_policy": "unknown"},
            },
            {
                "client_ref": "directory-ok",
                "target_name": "Working directory",
                "type": "directory",
                "directory": {"path": str(root)},
                "detectors": ["email"],
            },
            {
                "client_ref": "postgres-fails",
                "target_name": "Missing PostgreSQL database",
                "type": "database",
                "database": {
                    "engine": "postgresql",
                    "host": "127.0.0.1",
                    "port": 55432,
                    "database": "missing_batch_database",
                    "username": "postgres",
                    "password": password,
                    "tls_mode": "disable",
                },
                "scope": {"schemas": ["public"]},
                "detectors": ["email"],
            },
        ],
    }

    try:
        missing = request(
            app, "GET", f"/api/v1/batches/{uuid4()}/status", token=token
        )
        assert missing[0] == 404
        assert missing[1]["code"] == "batch_not_found"

        created = request(app, "POST", "/api/v1/batches", payload, token)
        assert created[0] == 202
        assert [job["client_ref"] for job in created[1]["jobs"]] == [
            "postgres-ok",
            "directory-ok",
            "postgres-fails",
        ]
        status = _wait_for_batch(app, created[1]["batch_id"], token)
        assert status[0] == 200
        assert status[1]["status"] == "completed_with_failures"
        jobs = {job["target_name"]: job for job in status[1]["jobs"]}
        assert jobs["Working PostgreSQL"]["status"] == "completed_with_warnings"
        assert jobs["Working PostgreSQL"]["matches_found"] == 1
        assert jobs["Working directory"]["status"] == "completed"
        assert jobs["Working directory"]["matches_found"] == 1
        assert jobs["Missing PostgreSQL database"]["status"] == "failed"
        assert jobs["Missing PostgreSQL database"]["error_code"] == (
            "target_access_failed"
        )

        with sessions() as database:
            persisted = json.dumps(
                {
                    "batches": [
                        batch.label
                        for batch in database.scalars(select(ScanBatch))
                    ],
                    "jobs": [
                        {
                            "display": job.target_display,
                            "detectors": job.detector_config_json,
                            "governance": job.governance_context_json,
                            "evidence": job.control_evidence_json,
                            "error": job.error_message,
                        }
                        for job in database.scalars(select(ScanJob))
                    ],
                    "inventory": [
                        {
                            "location": item.location_locator,
                            "field": item.field_locator,
                            "type": item.pii_type,
                            "count": item.match_count,
                        }
                        for item in database.scalars(select(ScanInventoryItem))
                    ],
                    "audit": [
                        {
                            "action": event.action,
                            "details": event.details_json,
                        }
                        for event in database.scalars(select(AuditEvent))
                    ],
                }
            )
        assert password not in persisted
        assert pii_value not in persisted

        active_root = tmp_path / "active"
        active_root.mkdir()
        monkeypatch.setattr(scan_routes, "submit_directory_job", lambda **_: None)
        active_payload = {
            "label": "Active target",
            "targets": [
                {
                    "client_ref": "active",
                    "target_name": "Active directory",
                    "type": "directory",
                    "directory": {"path": str(active_root)},
                    "detectors": ["email"],
                }
            ],
        }
        active = request(app, "POST", "/api/v1/batches", active_payload, token)
        assert active[0] == 202
        pending = request(
            app,
            "GET",
            active[1]["batch_status_url"],
            token=token,
        )
        assert pending[1]["status"] == "pending"
        conflict = request(
            app, "POST", "/api/v1/batches", active_payload, token
        )
        assert conflict[0] == 409
        assert conflict[1]["code"] == "target_scan_active"
        assert password not in json.dumps(conflict[1])
    finally:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS batch_fixture CASCADE"))
        command.downgrade(config, "base")
        engine.dispose()


def test_restart_lifespan_fails_orphaned_jobs(tmp_path, monkeypatch) -> None:
    database_url = os.getenv("TEST_APP_DB_URL")
    if not database_url:
        pytest.fail("TEST_APP_DB_URL is required for Task 9 verification")
    config, engine, sessions, user_id, _ = _setup(database_url, monkeypatch)
    now = datetime.now(timezone.utc)
    batch_id = uuid4()
    jobs = []
    with sessions() as database:
        database.add(
            ScanBatch(id=batch_id, label="Restart test", created_by=user_id)
        )
        for index, status in enumerate(("pending", "validating", "running")):
            job = ScanJob(
                id=uuid4(),
                batch_id=batch_id,
                target_name=f"Orphan {status}",
                target_type="directory",
                target_engine=None,
                target_display=str(tmp_path / status),
                target_fingerprint=str(index) * 64,
                status=status,
                started_at=now if status == "running" else None,
            )
            jobs.append(job.id)
            database.add(job)
        completed = ScanJob(
            id=uuid4(),
            batch_id=batch_id,
            target_name="Already completed",
            target_type="directory",
            target_engine=None,
            target_display=str(tmp_path / "completed"),
            target_fingerprint="c" * 64,
            status="completed",
            stage="completed",
            progress_percent=100,
            coverage_status="complete",
            permission_check_status="not_applicable",
            finished_at=now,
        )
        database.add(completed)
        database.commit()

    coordinator._DATABASE_TARGETS[jobs[0]] = object()
    app = create_app()

    async def run_lifespan():
        async with app.router.lifespan_context(app):
            pass

    try:
        asyncio.run(run_lifespan())
        with sessions() as database:
            for job_id in jobs:
                orphan = database.get(ScanJob, job_id)
                assert orphan.status == "failed"
                assert orphan.stage == "failed"
                assert orphan.coverage_status == "failed"
                assert orphan.error_code == "access_context_lost"
                assert orphan.finished_at is not None
            assert database.get(ScanJob, completed.id).status == "completed"
        assert coordinator._DATABASE_TARGETS == {}
    finally:
        command.downgrade(config, "base")
        engine.dispose()
