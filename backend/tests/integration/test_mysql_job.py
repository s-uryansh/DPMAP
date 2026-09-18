import json
import os
from pathlib import Path
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from alembic import command
from alembic.config import Config
import mysql.connector
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from dpmap.core.security import encode_access_token, hash_password
from dpmap.db.models import AuthSession, ScanInventoryItem, User
from dpmap.db.session import _session_factory
from dpmap.engine.scanners import mysql as mysql_scanner
from dpmap.jobs.coordinator import _DATABASE_TARGETS
from dpmap.main import create_app
from asgi import request


BACKEND_ROOT = Path(__file__).parents[2]


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
    raise AssertionError("MySQL scan did not finish")


def _execute(connection, statement: str, parameters=None):
    with connection.cursor(buffered=True) as cursor:
        cursor.execute(statement, parameters)
        return cursor.fetchall() if cursor.with_rows else []


def _random_password_user(connection, username: str) -> str:
    password = secrets.token_urlsafe(32)
    _execute(
        connection,
        f"CREATE USER '{username}'@'%' IDENTIFIED BY %s",
        (password,),
    )
    return password


def _reset_trace(connection) -> None:
    _execute(
        connection,
        "TRUNCATE TABLE performance_schema.events_statements_history_long",
    )


def _statement_trace(connection) -> list[tuple[str, str | None, int]]:
    thread_rows = _execute(
        connection,
        """
        SELECT THREAD_ID
        FROM performance_schema.events_statements_history_long
        WHERE SQL_TEXT =
          'SET SESSION TRANSACTION READ ONLY /* dpmap-readonly-scan */'
        ORDER BY TIMER_START DESC LIMIT 1
        """,
    )
    assert thread_rows, "marked scanner thread missing from Performance Schema"
    return _execute(
        connection,
        """
        SELECT EVENT_NAME, SQL_TEXT, MYSQL_ERRNO
        FROM performance_schema.events_statements_history_long
        WHERE THREAD_ID = %s AND EVENT_NAME LIKE 'statement/sql/%%'
        ORDER BY EVENT_ID
        """,
        (thread_rows[0][0],),
    )


def _assert_approved_trace(trace: list[tuple[str, str | None, int]]) -> None:
    assert trace
    assert {event for event, _, _ in trace} <= {
        "statement/sql/begin",
        "statement/sql/rollback",
        "statement/sql/select",
        "statement/sql/set_option",
    }
    for event, statement, error_number in trace:
        if statement is None:
            assert event == "statement/sql/select" and error_number == 3024
            continue
        normalized = " ".join(statement.split()).upper()
        assert (
            normalized.startswith("SELECT ")
            or normalized.startswith("SET NAMES ")
            or normalized
            in {
                "SET @@SESSION.AUTOCOMMIT = OFF",
                "SET SESSION TRANSACTION READ ONLY /* DPMAP-READONLY-SCAN */",
                "SET TRANSACTION READ ONLY",
                "START TRANSACTION",
                "ROLLBACK",
            }
        ), statement
    assert any(
        statement
        and "SET SESSION TRANSACTION READ ONLY" in statement.upper()
        for _, statement, _ in trace
    )
    assert any(
        statement and "SET TRANSACTION READ ONLY" in statement.upper()
        for _, statement, _ in trace
    )
    assert any(
        statement and statement.strip().upper() == "START TRANSACTION"
        for _, statement, _ in trace
    )
    assert any(
        statement and statement.strip().upper() == "ROLLBACK"
        for _, statement, _ in trace
    )


def _scan_payload(
    username: str, password: str, database: str = "scan_fixture"
):
    return {
        "label": "MySQL test",
        "target_name": "Fixture database",
        "host": "127.0.0.1",
        "port": int(os.environ["TEST_MYSQL_PORT"]),
        "database": database,
        "username": username,
        "password": password,
        "tls_mode": "required",
        "detectors": ["pan", "aadhaar", "phone", "email"],
    }


def test_mysql_job_is_read_only_streamed_and_secret_free(monkeypatch) -> None:
    database_url = os.getenv("TEST_APP_DB_URL")
    mysql_port = os.getenv("TEST_MYSQL_PORT")
    if not database_url or not mysql_port:
        pytest.skip("TEST_APP_DB_URL and TEST_MYSQL_PORT are required")

    admin = mysql.connector.connect(
        host="127.0.0.1",
        port=int(mysql_port),
        user="root",
        password="",
        ssl_disabled=True,
        autocommit=True,
    )
    config = _alembic_config(database_url)
    engine = create_engine(database_url)
    sessions = sessionmaker(engine, expire_on_commit=False)
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    _execute(
        admin,
        "UPDATE performance_schema.setup_consumers SET ENABLED = 'YES' "
        "WHERE NAME = 'events_statements_history_long'",
    )
    assert _execute(
        admin,
        "SELECT ENABLED FROM performance_schema.setup_consumers "
        "WHERE NAME = 'events_statements_history_long'",
    ) == [("YES",)]
    assert _execute(admin, "SELECT VERSION()")[0][0].startswith("8.4.")
    _execute(admin, "DROP DATABASE IF EXISTS scan_fixture")
    _execute(admin, "DROP DATABASE IF EXISTS scan_slow")
    _execute(admin, "CREATE DATABASE scan_fixture")
    _execute(admin, "CREATE DATABASE scan_slow")
    _execute(
        admin,
        """
        CREATE TABLE scan_fixture.`People Records` (
            `PAN Code` VARCHAR(32), email TEXT, phone CHAR(10), payload JSON,
            mood ENUM('calm', 'busy'), ignored BLOB, unsupported INT
        )
        """,
    )
    _execute(
        admin,
        """
        INSERT INTO scan_fixture.`People Records`
        VALUES (%s, %s, %s, %s, 'busy', %s, 7),
               (NULL, %s, NULL, %s, 'calm', NULL, 8)
        """,
        (
            "ABCDE1234F",
            "audit@example.in",
            "9876543210",
            json.dumps({"aadhaar": "9999 9999 0019"}),
            b"audit@example.in",
            "not-pii",
            json.dumps({"note": "clean"}),
        ),
    )
    _execute(admin, "CREATE TABLE scan_slow.locked (value TEXT)")
    _execute(
        admin,
        "INSERT INTO scan_slow.locked VALUES (%s)",
        ("timeout@example.in",),
    )
    for username in ("dpmap_fixture_reader", "dpmap_fixture_privileged"):
        _execute(admin, f"DROP USER IF EXISTS '{username}'@'%'")
    reader_password = _random_password_user(admin, "dpmap_fixture_reader")
    privileged_password = _random_password_user(
        admin, "dpmap_fixture_privileged"
    )
    _execute(
        admin,
        "GRANT SELECT ON scan_fixture.* TO 'dpmap_fixture_reader'@'%'",
    )
    _execute(
        admin,
        "GRANT SELECT ON scan_slow.* TO 'dpmap_fixture_reader'@'%'",
    )
    _execute(
        admin,
        "GRANT ALL PRIVILEGES ON *.* TO 'dpmap_fixture_privileged'@'%'",
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
                email="mysql-scanner@example.test",
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
        denied = request(app, "POST", "/api/v1/scans/mysql", denied_payload, token)
        assert denied[0] == 422
        assert denied[1]["code"] == "database_host_not_allowed"
        assert reader_password not in json.dumps(denied[1])

        _reset_trace(admin)
        created = request(
            app,
            "POST",
            "/api/v1/scans/mysql",
            _scan_payload("dpmap_fixture_reader", reader_password),
            token,
        )
        assert created[0] == 202
        status = _wait_for_terminal(app, created[1]["job_id"], token)
        assert status[0] == 200
        assert status[1]["status"] == "completed_with_warnings", status[1]
        assert status[1]["permission_check_status"] == "verified_limited"
        assert status[1]["coverage_status"] == "partial"
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
            assert {
                (item.field_locator, item.pii_type, item.match_count)
                for item in items
            } == {
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

        trace = _statement_trace(admin)
        _assert_approved_trace(trace)
        serialized_trace = json.dumps(trace)
        for canary in (
            reader_password,
            "ABCDE1234F",
            "audit@example.in",
            "9876543210",
            "9999 9999 0019",
        ):
            assert canary not in serialized_trace
        assert any(
            statement
            and "`PAN Code` FROM `scan_fixture`.`People Records`" in statement
            for _, statement, _ in trace
        )

        _reset_trace(admin)
        privileged = request(
            app,
            "POST",
            "/api/v1/scans/mysql",
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
        privileged_trace = _statement_trace(admin)
        _assert_approved_trace(privileged_trace)
        assert privileged_password not in json.dumps(privileged_trace)

        blocker = mysql.connector.connect(
            host="127.0.0.1",
            port=int(mysql_port),
            user="root",
            password="",
            ssl_disabled=True,
            autocommit=True,
        )
        try:
            _execute(blocker, "LOCK TABLES scan_slow.locked WRITE")
            _reset_trace(admin)
            monkeypatch.setattr(mysql_scanner, "STATEMENT_TIMEOUT_MS", 50)
            timed = request(
                app,
                "POST",
                "/api/v1/scans/mysql",
                _scan_payload(
                    "dpmap_fixture_reader", reader_password, "scan_slow"
                ),
                token,
            )
            timed_status = _wait_for_terminal(app, timed[1]["job_id"], token)
            assert timed_status[1]["status"] == "failed"
            assert timed_status[1]["error_code"] == "target_timeout"
            assert reader_password not in json.dumps(timed_status[1])
        finally:
            _execute(blocker, "UNLOCK TABLES")
            blocker.close()
        timeout_trace = _statement_trace(admin)
        _assert_approved_trace(timeout_trace)
        assert any(
            event == "statement/sql/select"
            and statement is None
            and error_number == 3024
            for event, statement, error_number in timeout_trace
        )
        assert _execute(
            admin,
            "SELECT COUNT(*) FROM information_schema.processlist "
            "WHERE USER = 'dpmap_fixture_reader'",
        ) == [(0,)]

        missing_password = secrets.token_urlsafe(32)
        inaccessible = request(
            app,
            "POST",
            "/api/v1/scans/mysql",
            _scan_payload("dpmap_missing_reader", missing_password),
            token,
        )
        inaccessible_status = _wait_for_terminal(
            app, inaccessible[1]["job_id"], token
        )
        assert inaccessible_status[1]["status"] == "failed"
        assert inaccessible_status[1]["error_code"] == "target_access_failed"
        assert missing_password not in json.dumps(inaccessible_status[1])

        queued_payload = _scan_payload(
            "dpmap_fixture_reader", reader_password
        )
        queued_payload["detectors"] = ["email"]
        with monkeypatch.context() as patch:
            patch.setattr(
                "dpmap.api.routes.scans.submit_mysql_job", lambda **_: None
            )
            queued = request(
                app, "POST", "/api/v1/scans/mysql", queued_payload, token
            )
            conflict = request(
                app, "POST", "/api/v1/scans/mysql", queued_payload, token
            )
        assert queued[0] == 202
        assert conflict[0] == 409
        assert conflict[1]["code"] == "target_scan_active"
    finally:
        _session_factory.cache_clear()
        _execute(admin, "DROP DATABASE IF EXISTS scan_fixture")
        _execute(admin, "DROP DATABASE IF EXISTS scan_slow")
        for username in ("dpmap_fixture_reader", "dpmap_fixture_privileged"):
            _execute(admin, f"DROP USER IF EXISTS '{username}'@'%'")
        admin.close()
        command.downgrade(config, "base")
        engine.dispose()
