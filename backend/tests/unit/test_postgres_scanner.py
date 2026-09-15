import psycopg
import pytest

from dpmap.engine.scanners import postgres
from dpmap.jobs import coordinator
from uuid import uuid4


def _target_kwargs():
    return {
        "host": "DB.EXAMPLE.TEST.",
        "port": 5432,
        "database": "records",
        "username": "reader",
        "password": "runtime-secret",
        "tls_mode": "verify-full",
        "schemas": ("public",),
        "allowed_hosts": " db.example.test, ",
        "allow_insecure_tls": False,
    }


def test_postgres_target_boundary_is_deny_by_default(monkeypatch) -> None:
    kwargs = _target_kwargs()
    with pytest.raises(postgres.PostgresScanError) as error:
        postgres.resolve_postgres_target(**(kwargs | {"allowed_hosts": None}))
    assert error.value.code == "database_hosts_not_configured"

    with pytest.raises(postgres.PostgresScanError) as error:
        postgres.resolve_postgres_target(
            **(kwargs | {"allowed_hosts": "other.example.test"})
        )
    assert error.value.code == "database_host_not_allowed"

    with pytest.raises(postgres.PostgresScanError) as error:
        postgres.resolve_postgres_target(
            **(kwargs | {"tls_mode": "disable"})
        )
    assert error.value.code == "insecure_tls_not_allowed"

    monkeypatch.setattr(
        postgres.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
    )
    with pytest.raises(postgres.PostgresScanError) as error:
        postgres.resolve_postgres_target(**kwargs)
    assert error.value.code == "database_host_unavailable"

    monkeypatch.setattr(postgres.socket, "getaddrinfo", lambda *_a, **_k: [])
    with pytest.raises(postgres.PostgresScanError) as error:
        postgres.resolve_postgres_target(**kwargs)
    assert error.value.code == "database_host_unavailable"

    monkeypatch.setattr(
        postgres.socket,
        "getaddrinfo",
        lambda *_a, **_k: [(2, 1, 6, "", ("192.0.2.8", 5432))],
    )
    target = postgres.resolve_postgres_target(**kwargs)
    assert target.host == "db.example.test"
    assert target.hostaddr == "192.0.2.8"
    assert "runtime-secret" not in repr(target)


def test_postgres_scanner_sanitizes_driver_errors(monkeypatch) -> None:
    target = postgres.PostgresTarget(
        "db.example.test",
        "192.0.2.8",
        5432,
        "records",
        "reader",
        "runtime-secret",
    )

    for exception, code in (
        (psycopg.OperationalError("runtime-secret"), "target_access_failed"),
        (psycopg.DatabaseError("runtime-secret"), "target_scan_failed"),
    ):
        monkeypatch.setattr(
            postgres.psycopg,
            "connect",
            lambda **_kwargs: (_ for _ in ()).throw(exception),
        )
        with pytest.raises(postgres.PostgresScanError) as error:
            postgres.scan_postgres(target, frozenset({"email"}), lambda _: None)
        assert error.value.code == code
        assert "runtime-secret" not in str(error.value)

    assert postgres._confidence_band(0.96) == "high"
    assert postgres._confidence_band(0.85) == "medium"
    assert postgres._confidence_band(0.5) == "low"


def test_postgres_scanner_rejects_missing_read_only_state(monkeypatch) -> None:
    class Context:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Cursor(Context):
        def execute(self, _query):
            return None

        def fetchone(self):
            return ("off",)

    class Connection(Context):
        read_only = False

        def transaction(self, **_kwargs):
            return Context()

        def cursor(self):
            return Cursor()

    monkeypatch.setattr(postgres.psycopg, "connect", lambda **_kwargs: Connection())
    target = postgres.PostgresTarget(
        "db.example.test", "192.0.2.8", 5432, "records", "reader", "secret"
    )
    with pytest.raises(postgres.PostgresScanError) as error:
        postgres.scan_postgres(target, frozenset({"email"}), lambda _: None)
    assert error.value.code == "read_only_not_enforced"


def test_postgres_total_deadline_stops_before_column(monkeypatch) -> None:
    class Context:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def transaction(self, **_kwargs):
            return self

        def cursor(self):
            return self

        def execute(self, _query):
            return None

        def fetchone(self):
            return ("on",)

    connection = Context()
    monkeypatch.setattr(postgres.psycopg, "connect", lambda **_kwargs: connection)
    monkeypatch.setattr(postgres, "_permission_status", lambda *_: "unverifiable")
    monkeypatch.setattr(
        postgres,
        "_discover_columns",
        lambda *_: ([('public', 'records', 'value', 'S', 'text', 'b')], 0),
    )
    times = iter((0.0, postgres.TOTAL_JOB_TIMEOUT_SECONDS + 1))
    monkeypatch.setattr(postgres.time, "monotonic", lambda: next(times))
    target = postgres.PostgresTarget(
        "db.example.test", "192.0.2.8", 5432, "records", "reader", "secret"
    )
    with pytest.raises(postgres.PostgresScanError) as error:
        postgres.scan_postgres(target, frozenset({"email"}), lambda _: None)
    assert error.value.code == "target_timeout"

    class StreamingCursor:
        itersize = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _query):
            return None

        def __iter__(self):
            return iter((("value",),))

    stream_connection = type(
        "Connection",
        (),
        {"cursor": lambda self, **_kwargs: StreamingCursor()},
    )()
    monkeypatch.setattr(postgres.time, "monotonic", lambda: 2.0)
    with pytest.raises(postgres.PostgresScanError) as error:
        postgres._scan_column(
            stream_connection,
            ("public", "records", "value", "S", "text", "b"),
            frozenset({"email"}),
            0,
            1.0,
        )
    assert error.value.code == "target_timeout"


def test_postgres_coordinator_clears_secret_if_submit_fails(monkeypatch) -> None:
    job_id = uuid4()
    target = postgres.PostgresTarget(
        "db.example.test", "192.0.2.8", 5432, "records", "reader", "secret"
    )
    monkeypatch.setattr(
        coordinator._EXECUTOR,
        "submit",
        lambda *_args: (_ for _ in ()).throw(RuntimeError()),
    )
    with pytest.raises(RuntimeError):
        coordinator.submit_postgres_job(
            job_id=job_id,
            target=target,
            detectors=frozenset({"email"}),
            database_url="unused",
        )
    assert job_id not in coordinator._DATABASE_TARGETS
    coordinator._run_postgres_job(uuid4(), frozenset({"email"}), "unused")
