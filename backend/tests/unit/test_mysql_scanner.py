from uuid import uuid4

from mysql.connector import errors
import pytest

from dpmap.engine.scanners import mysql
from dpmap.jobs import coordinator


def _target_kwargs():
    return {
        "host": "DB.EXAMPLE.TEST.",
        "port": 3306,
        "database": "records",
        "username": "reader",
        "password": "runtime-secret",
        "tls_mode": "disable",
        "ssl_ca": None,
        "allowed_hosts": " db.example.test, ",
        "allow_insecure_tls": True,
    }


def test_mysql_target_boundary_is_deny_by_default(monkeypatch) -> None:
    kwargs = _target_kwargs()
    with pytest.raises(mysql.MySQLScanError) as error:
        mysql.resolve_mysql_target(**(kwargs | {"allowed_hosts": None}))
    assert error.value.code == "database_hosts_not_configured"

    with pytest.raises(mysql.MySQLScanError) as error:
        mysql.resolve_mysql_target(
            **(kwargs | {"allowed_hosts": "other.example.test"})
        )
    assert error.value.code == "database_host_not_allowed"

    with pytest.raises(mysql.MySQLScanError) as error:
        mysql.resolve_mysql_target(**(kwargs | {"allow_insecure_tls": False}))
    assert error.value.code == "insecure_tls_not_allowed"

    with pytest.raises(mysql.MySQLScanError) as error:
        mysql.resolve_mysql_target(
            **(kwargs | {"tls_mode": "verify-identity"})
        )
    assert error.value.code == "mysql_tls_ca_required"

    monkeypatch.setattr(
        mysql.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
    )
    with pytest.raises(mysql.MySQLScanError) as error:
        mysql.resolve_mysql_target(**kwargs)
    assert error.value.code == "database_host_unavailable"

    monkeypatch.setattr(mysql.socket, "getaddrinfo", lambda *_args, **_kwargs: [])
    with pytest.raises(mysql.MySQLScanError) as error:
        mysql.resolve_mysql_target(**kwargs)
    assert error.value.code == "database_host_unavailable"

    monkeypatch.setattr(
        mysql.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("192.0.2.8", 3306))],
    )
    target = mysql.resolve_mysql_target(**kwargs)
    assert target.host == "db.example.test"
    assert target.hostaddr == "192.0.2.8"
    assert "runtime-secret" not in repr(target)


def test_mysql_tls_and_error_mapping(monkeypatch) -> None:
    target = mysql.MySQLTarget(
        "db.example.test",
        "192.0.2.8",
        3306,
        "records",
        "reader",
        "runtime-secret",
        tls_mode="disable",
    )
    assert mysql._tls_options(target) == {"ssl_disabled": True}
    assert mysql._tls_options(
        mysql.MySQLTarget(
            "host", "address", 3306, "db", "user", "secret", "required"
        )
    ) == {"ssl_disabled": False}
    verify_ca = mysql.MySQLTarget(
        "host", "address", 3306, "db", "user", "secret", "verify-ca", "/ca"
    )
    assert mysql._tls_options(verify_ca) == {
        "ssl_disabled": False,
        "ssl_ca": "/ca",
        "ssl_verify_cert": True,
    }
    assert mysql._tls_options(
        mysql.MySQLTarget(
            "host", "address", 3306, "db", "user", "secret", "verify-identity", "/ca"
        )
    )["ssl_verify_identity"]

    for exception, code in (
        (errors.ProgrammingError("runtime-secret", errno=1045), "target_access_failed"),
        (errors.ReadTimeoutError("runtime-secret"), "target_timeout"),
        (errors.DatabaseError("runtime-secret", errno=1205), "target_timeout"),
        (errors.DatabaseError("runtime-secret", errno=9999), "target_scan_failed"),
    ):
        monkeypatch.setattr(
            mysql.mysql.connector,
            "connect",
            lambda **_kwargs: (_ for _ in ()).throw(exception),
        )
        with pytest.raises(mysql.MySQLScanError) as error:
            mysql.scan_mysql(target, frozenset({"email"}), lambda _: None)
        assert error.value.code == code
        assert "runtime-secret" not in str(error.value)

    assert mysql._identifier("odd`name") == "`odd``name`"
    assert mysql._confidence_band(0.96) == "high"
    assert mysql._confidence_band(0.85) == "medium"
    assert mysql._confidence_band(0.5) == "low"


def test_mysql_scanner_rejects_missing_read_only_state(monkeypatch) -> None:
    closed = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _query):
            return None

        def fetchone(self):
            return (0,)

    class Connection:
        def cursor(self, **_kwargs):
            return Cursor()

        def start_transaction(self, **_kwargs):
            return None

        def rollback(self):
            raise errors.DatabaseError("rollback failed")

        def close(self):
            closed.append(True)

    monkeypatch.setattr(mysql.mysql.connector, "connect", lambda **_: Connection())
    target = mysql.MySQLTarget(
        "host", "address", 3306, "db", "user", "secret", "disable"
    )
    with pytest.raises(mysql.MySQLScanError) as error:
        mysql.scan_mysql(target, frozenset({"email"}), lambda _: None)
    assert error.value.code == "read_only_not_enforced"
    assert closed == [True]


def test_mysql_total_deadline_stops_before_and_during_column(monkeypatch) -> None:
    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _query):
            return None

        def fetchone(self):
            return (1,)

    class Connection:
        def cursor(self, **_kwargs):
            return Cursor()

        def start_transaction(self, **_kwargs):
            return None

        def rollback(self):
            return None

        def close(self):
            return None

    connection = Connection()
    monkeypatch.setattr(mysql.mysql.connector, "connect", lambda **_: connection)
    monkeypatch.setattr(mysql, "_permission_status", lambda *_: "unverifiable")
    monkeypatch.setattr(
        mysql,
        "_discover_columns",
        lambda *_: ([("records", "items", "value", "text")], 0),
    )
    times = iter((0.0, mysql.TOTAL_JOB_TIMEOUT_SECONDS + 1))
    monkeypatch.setattr(mysql.time, "monotonic", lambda: next(times))
    target = mysql.MySQLTarget(
        "host", "address", 3306, "db", "user", "secret", "disable"
    )
    with pytest.raises(mysql.MySQLScanError) as error:
        mysql.scan_mysql(target, frozenset({"email"}), lambda _: None)
    assert error.value.code == "target_timeout"

    class StreamingCursor:
        def execute(self, _query):
            return None

        def fetchmany(self, _size):
            return [("value",)]

        def close(self):
            return None

    stream_connection = type(
        "Connection",
        (),
        {"cursor": lambda self, **_kwargs: StreamingCursor()},
    )()
    monkeypatch.setattr(mysql.time, "monotonic", lambda: 2.0)
    with pytest.raises(mysql.MySQLScanError) as error:
        mysql._scan_column(
            stream_connection,
            ("records", "items", "value", "text"),
            frozenset({"email"}),
            1.0,
        )
    assert error.value.code == "target_timeout"


def test_mysql_coordinator_clears_secret_if_submit_fails(monkeypatch) -> None:
    job_id = uuid4()
    target = mysql.MySQLTarget(
        "host", "address", 3306, "db", "user", "secret", "disable"
    )
    monkeypatch.setattr(
        coordinator._EXECUTOR,
        "submit",
        lambda *_args: (_ for _ in ()).throw(RuntimeError()),
    )
    with pytest.raises(RuntimeError):
        coordinator.submit_mysql_job(
            job_id=job_id,
            target=target,
            detectors=frozenset({"email"}),
            database_url="unused",
        )
    assert job_id not in coordinator._DATABASE_TARGETS
    coordinator._run_mysql_job(uuid4(), frozenset({"email"}), "unused")
