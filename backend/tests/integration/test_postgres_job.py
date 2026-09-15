import json
import os
from pathlib import Path
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from psycopg import sql
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from dpmap.core.security import encode_access_token, hash_password
from dpmap.db.models import AuthSession, ScanInventoryItem, User
from dpmap.db.session import _session_factory
from dpmap.engine.scanners.postgres import PostgresTarget
from dpmap.jobs import coordinator
from dpmap.jobs.coordinator import _DATABASE_TARGETS
from dpmap.main import create_app
from asgi import request


BACKEND_ROOT = Path(__file__).parents[2]
TRACE_PREFIXES = {"BEGIN", "CLOSE", "DECLARE", "FETCH", "ROLLBACK", "SELECT"}


def _alembic_config(database_url: str) -> Config:
    config = Config(BACKEND_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def _wait_for_terminal(app, job_id, token):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response = request(app, "GET", f"/api/v1/jobs/{job_id}/status", token=token)
        if response[1]["status"] in {
            "completed",
            "completed_with_warnings",
            "failed",
        }:
            return response
        time.sleep(0.05)
    raise AssertionError("PostgreSQL scan did not finish")


def _scan_payload(username: str, password: str, schema: str = "scan_fixture"):
    return {
        "label": "PostgreSQL test",
        "target_name": "Fixture database",
        "host": "127.0.0.1",
        "port": 55432,
        "database": "dpmap_test",
        "username": username,
        "password": password,
        "tls_mode": "disable",
        "schemas": [schema],
        "detectors": ["pan", "aadhaar", "phone", "email"],
    }


def _statement_trace(connection, role: str) -> list[str]:
    return list(
        connection.scalars(
            text(
                "SELECT query FROM pg_stat_statements "
                "JOIN pg_roles ON pg_roles.oid = pg_stat_statements.userid "
                "WHERE rolname = :role ORDER BY query"
            ),
            {"role": role},
        )
    )


def _assert_approved_trace(trace: list[str]) -> None:
    assert trace
    prefixes = {
        statement.lstrip().split(maxsplit=1)[0].upper() for statement in trace
    }
    assert prefixes <= TRACE_PREFIXES
    assert any(
        statement.lstrip().upper().startswith("BEGIN READ ONLY")
        for statement in trace
    )
    assert any(
        statement.lstrip().upper().startswith("ROLLBACK")
        for statement in trace
    )


def test_postgres_job_is_read_only_streamed_and_secret_free(monkeypatch) -> None:
    database_url = os.getenv("TEST_APP_DB_URL")
    if not database_url:
        pytest.skip("TEST_APP_DB_URL is required for PostgreSQL integration tests")

    reader_password = secrets.token_urlsafe(32)
    privileged_password = secrets.token_urlsafe(32)
    config = _alembic_config(database_url)
    engine = create_engine(database_url)
    sessions = sessionmaker(engine, expire_on_commit=False)
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    with engine.begin() as connection:
        extension = connection.scalar(
            text(
                "SELECT extname FROM pg_extension "
                "WHERE extname = 'pg_stat_statements'"
            )
        )
        assert extension == "pg_stat_statements"
        connection.execute(text("DROP SCHEMA IF EXISTS scan_fixture CASCADE"))
        connection.execute(text("DROP SCHEMA IF EXISTS scan_slow CASCADE"))
        connection.execute(text("DROP ROLE IF EXISTS dpmap_fixture_reader"))
        connection.execute(text("DROP ROLE IF EXISTS dpmap_fixture_privileged"))
        driver = connection.connection.driver_connection
        driver.execute(
            sql.SQL("CREATE ROLE dpmap_fixture_reader LOGIN PASSWORD {}").format(
                sql.Literal(reader_password)
            )
        )
        driver.execute(
            sql.SQL(
                "CREATE ROLE dpmap_fixture_privileged LOGIN CREATEDB PASSWORD {}"
            ).format(sql.Literal(privileged_password))
        )
        connection.execute(text("CREATE SCHEMA scan_fixture"))
        connection.execute(text("CREATE SCHEMA scan_slow"))
        connection.execute(
            text("CREATE TYPE scan_fixture.mood AS ENUM ('calm', 'busy')")
        )
        connection.execute(
            text(
                'CREATE TABLE scan_fixture."People Records" '
                '("PAN Code" text, email text, phone text, '
                "payload jsonb, mood scan_fixture.mood, ignored bytea)"
            )
        )
        connection.execute(text('CREATE TABLE scan_slow.locked (value text)'))
        connection.execute(
            text(
                'INSERT INTO scan_fixture."People Records" VALUES '
                "(:pan, :email, :phone, CAST(:payload AS jsonb), 'busy', "
                ":ignored), (NULL, :clean, NULL, CAST(:payload2 AS jsonb), "
                "'calm', NULL)"
            ),
            {
                "pan": "ABCDE1234F",
                "email": "audit@example.in",
                "phone": "9876543210",
                "payload": json.dumps({"aadhaar": "9999 9999 0019"}),
                "clean": "not-pii",
                "payload2": json.dumps({"note": "clean"}),
                "ignored": b"audit@example.in",
            },
        )
        connection.execute(
            text("INSERT INTO scan_slow.locked VALUES ('audit@example.in')")
        )
        connection.execute(
            text(
                "GRANT USAGE ON SCHEMA scan_fixture, scan_slow "
                "TO dpmap_fixture_reader, dpmap_fixture_privileged"
            )
        )
        connection.execute(
            text(
                "GRANT SELECT ON ALL TABLES IN SCHEMA scan_fixture, scan_slow "
                "TO dpmap_fixture_reader, dpmap_fixture_privileged"
            )
        )

    jwt_secret = secrets.token_urlsafe(48)
    monkeypatch.setenv("JWT_SECRET", jwt_secret)
    monkeypatch.setenv("APP_DB_URL", database_url)
    monkeypatch.setenv("ALLOWED_DB_HOSTS", "127.0.0.1")
    monkeypatch.setenv("ALLOW_INSECURE_TARGET_TLS", "true")
    now = datetime.now(timezone.utc)
    user_id, jti = uuid4(), uuid4()
    with sessions() as database:
        database.add(
            User(
                id=user_id,
                email="scanner@example.test",
                role="admin",
                password_hash=hash_password("test-password-long-enough"),
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
    app = create_app()

    try:
        denied_payload = _scan_payload("dpmap_fixture_reader", reader_password)
        denied_payload["host"] = "not-allowed.example.test"
        denied = request(
            app, "POST", "/api/v1/scans/postgres", denied_payload, token
        )
        assert denied[0] == 422
        assert denied[1]["code"] == "database_host_not_allowed"
        assert reader_password not in json.dumps(denied[1])

        with engine.begin() as connection:
            connection.execute(text("SELECT pg_stat_statements_reset()"))

        created = request(
            app,
            "POST",
            "/api/v1/scans/postgres",
            _scan_payload("dpmap_fixture_reader", reader_password),
            token,
        )
        assert created[0] == 202
        status = _wait_for_terminal(app, created[1]["job_id"], token)
        assert status[0] == 200
        assert status[1]["status"] == "completed_with_warnings"
        assert status[1]["permission_check_status"] == "verified_limited"
        assert status[1]["matches_found"] == 4
        assert status[1]["locations_scanned"] == 5
        assert status[1]["units_scanned"] == 10
        assert created[1]["job_id"] not in _DATABASE_TARGETS

        with sessions() as database:
            items = list(
                database.scalars(
                    select(ScanInventoryItem).where(
                        ScanInventoryItem.job_id == created[1]["job_id"]
                    )
                )
            )
            actual = {
                (item.field_locator, item.pii_type, item.match_count)
                for item in items
            }
            assert actual == {
                ("PAN Code", "pan", 1),
                ("email", "email", 1),
                ("phone", "phone", 1),
                ("payload", "aadhaar", 1),
            }
            persisted = json.dumps(
                [item.__dict__ for item in items], default=str
            ) + json.dumps(status[1], default=str)
            for canary in (
                reader_password,
                "ABCDE1234F",
                "audit@example.in",
                "9876543210",
                "9999 9999 0019",
            ):
                assert canary not in persisted

        with engine.connect() as connection:
            trace = _statement_trace(connection, "dpmap_fixture_reader")
        _assert_approved_trace(trace)
        assert any(
            statement.lstrip().upper().startswith("DECLARE")
            for statement in trace
        )
        assert any(
            '"People Records"' in statement and '"PAN Code"' in statement
            for statement in trace
        )

        privileged = request(
            app,
            "POST",
            "/api/v1/scans/postgres",
            _scan_payload("dpmap_fixture_privileged", privileged_password),
            token,
        )
        privileged_status = _wait_for_terminal(
            app, privileged[1]["job_id"], token
        )
        assert (
            privileged_status[1]["permission_check_status"]
            == "overprivileged"
        )
        with engine.connect() as connection:
            privileged_trace = _statement_trace(
                connection, "dpmap_fixture_privileged"
            )
        _assert_approved_trace(privileged_trace)

        queued_payload = _scan_payload("dpmap_fixture_reader", reader_password)
        queued_payload["detectors"] = ["email"]
        with monkeypatch.context() as patch:
            patch.setattr(
                "dpmap.api.routes.scans.submit_postgres_job", lambda **_: None
            )
            queued = request(
                app,
                "POST",
                "/api/v1/scans/postgres",
                queued_payload,
                token,
            )
            conflict = request(
                app,
                "POST",
                "/api/v1/scans/postgres",
                queued_payload,
                token,
            )
        assert queued[0] == 202
        assert conflict[0] == 409
        assert conflict[1]["code"] == "target_scan_active"

        target = PostgresTarget(
            "127.0.0.1",
            "127.0.0.1",
            55432,
            "dpmap_test",
            "dpmap_fixture_reader",
            reader_password,
            tls_mode="verify-full",
            schemas=("scan_fixture",),
        )
        queued_job_id = UUID(queued[1]["job_id"])
        with coordinator._DATABASE_TARGETS_LOCK:
            _DATABASE_TARGETS[queued_job_id] = target
        with monkeypatch.context() as patch:
            patch.setattr(
                coordinator,
                "scan_postgres",
                lambda *_args: ("verified_limited", 0),
            )
            coordinator._run_postgres_job(
                queued_job_id, frozenset({"email"}), database_url
            )
        clean_status = request(
            app,
            "GET",
            f"/api/v1/jobs/{queued[1]['job_id']}/status",
            token=token,
        )
        assert clean_status[1]["status"] == "completed"

        with monkeypatch.context() as patch:
            patch.setattr(
                "dpmap.api.routes.scans.submit_postgres_job", lambda **_: None
            )
            broken = request(
                app,
                "POST",
                "/api/v1/scans/postgres",
                queued_payload,
                token,
            )
        broken_job_id = UUID(broken[1]["job_id"])
        with coordinator._DATABASE_TARGETS_LOCK:
            _DATABASE_TARGETS[broken_job_id] = target
        with monkeypatch.context() as patch:
            patch.setattr(
                coordinator,
                "scan_postgres",
                lambda *_args: (_ for _ in ()).throw(RuntimeError()),
            )
            coordinator._run_postgres_job(
                broken_job_id, frozenset({"email"}), database_url
            )
        broken_status = request(
            app,
            "GET",
            f"/api/v1/jobs/{broken[1]['job_id']}/status",
            token=token,
        )
        assert broken_status[1]["error_code"] == "target_scan_failed"

        missing_job = uuid4()
        with coordinator._DATABASE_TARGETS_LOCK:
            _DATABASE_TARGETS[missing_job] = target
        coordinator._run_postgres_job(
            missing_job, frozenset({"email"}), database_url
        )
        assert missing_job not in _DATABASE_TARGETS

        wrong_secret = secrets.token_urlsafe(32)
        inaccessible = request(
            app,
            "POST",
            "/api/v1/scans/postgres",
            _scan_payload("dpmap_missing_reader", wrong_secret),
            token,
        )
        inaccessible_status = _wait_for_terminal(
            app, inaccessible[1]["job_id"], token
        )
        assert inaccessible_status[1]["error_code"] == "target_access_failed"
        assert wrong_secret not in json.dumps(inaccessible_status[1])

        with engine.begin() as connection:
            connection.execute(text("SELECT pg_stat_statements_reset()"))
        with engine.connect() as blocker, blocker.begin():
            blocker.execute(
                text("LOCK TABLE scan_slow.locked IN ACCESS EXCLUSIVE MODE")
            )
            monkeypatch.setattr(
                "dpmap.engine.scanners.postgres.STATEMENT_TIMEOUT_MS", 50
            )
            timed = request(
                app,
                "POST",
                "/api/v1/scans/postgres",
                _scan_payload(
                    "dpmap_fixture_reader", reader_password, "scan_slow"
                ),
                token,
            )
            timed_status = _wait_for_terminal(
                app, timed[1]["job_id"], token
            )
            assert timed_status[1]["status"] == "failed"
            assert timed_status[1]["error_code"] == "target_timeout"
            assert reader_password not in timed_status[1]["error_message"]
            assert timed[1]["job_id"] not in _DATABASE_TARGETS
        with engine.connect() as connection:
            timeout_trace = _statement_trace(
                connection, "dpmap_fixture_reader"
            )
            active = connection.scalar(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE usename = 'dpmap_fixture_reader'"
                )
            )
            assert active == 0
        _assert_approved_trace(timeout_trace)
    finally:
        _session_factory.cache_clear()
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS scan_fixture CASCADE"))
            connection.execute(text("DROP SCHEMA IF EXISTS scan_slow CASCADE"))
            connection.execute(text("DROP ROLE IF EXISTS dpmap_fixture_reader"))
            connection.execute(text("DROP ROLE IF EXISTS dpmap_fixture_privileged"))
        command.downgrade(config, "base")
        engine.dispose()
