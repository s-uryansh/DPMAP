import asyncio
from types import SimpleNamespace
from uuid import uuid4

from dpmap.api.routes import scans
from dpmap.api.schemas import BatchCreateRequest
from dpmap.db.models import ScanJob
from dpmap.engine.scanners.directory import DirectoryScanError
from dpmap.engine.scanners.mysql import MySQLScanError, MySQLTarget
from dpmap.engine.scanners.postgres import PostgresScanError
from dpmap.main import create_app


class _Database:
    def __init__(self):
        self.items = []
        self.commits = 0

    def add(self, item):
        self.items.append(item)

    def add_all(self, items):
        self.items.extend(items)

    def commit(self):
        self.commits += 1
        for item in self.items:
            if isinstance(item, ScanJob) and item.status is None:
                item.status = "pending"

    def rollback(self):
        pass


def _database_target(engine="mysql"):
    tls_mode = "required" if engine == "mysql" else "require"
    return {
        "client_ref": engine,
        "target_name": f"{engine} target",
        "type": "database",
        "database": {
            "engine": engine,
            "host": "database.example.test",
            "port": 3306 if engine == "mysql" else 5432,
            "database": "records",
            "username": "reader",
            "password": "request-only-secret",
            "tls_mode": tls_mode,
        },
        "scope": {"schemas": ["public"]},
        "detectors": ["aadhaar"],
    }


def test_batch_preflight_failures_are_terminal_siblings(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    monkeypatch.setenv("APP_DB_URL", "postgresql://metadata")
    monkeypatch.setenv("ALLOWED_SCAN_ROOTS", "/allowed")
    database = _Database()
    principal = SimpleNamespace(
        database=database, user=SimpleNamespace(id=uuid4())
    )
    monkeypatch.setattr(scans, "configured_roots", lambda *_: ())
    monkeypatch.setattr(
        scans,
        "validate_directory",
        lambda *_: (_ for _ in ()).throw(
            DirectoryScanError("directory_missing", "Directory is unavailable")
        ),
    )
    request = BatchCreateRequest(
        label="failed preflight",
        targets=[
            {
                "client_ref": "directory",
                "target_name": "directory target",
                "type": "directory",
                "directory": {"path": "/allowed/missing"},
                "detectors": ["email"],
            }
        ],
    )
    response = scans.create_batch(request, principal)
    assert response.jobs[0].status == "failed"
    assert next(
        item for item in database.items if isinstance(item, ScanJob)
    ).error_code == "directory_missing"

    monkeypatch.setattr(
        scans,
        "resolve_postgres_target",
        lambda **_: (_ for _ in ()).throw(
            PostgresScanError("database_host_not_allowed", "Host denied")
        ),
    )
    postgres = scans._prepare_batch_job(
        BatchCreateRequest(
            label="postgres", targets=[_database_target("postgresql")]
        ).targets[0],
        uuid4(),
    )
    assert postgres.target is None
    assert postgres.job.error_code == "database_host_not_allowed"

    monkeypatch.setattr(
        scans,
        "resolve_mysql_target",
        lambda **_: (_ for _ in ()).throw(
            MySQLScanError("database_host_not_allowed", "Host denied")
        ),
    )
    mysql = scans._prepare_batch_job(
        BatchCreateRequest(
            label="mysql", targets=[_database_target()]
        ).targets[0],
        uuid4(),
    )
    assert mysql.target is None
    assert mysql.job.error_code == "database_host_not_allowed"


def test_mysql_batch_submission_and_submit_failure(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    monkeypatch.setenv("APP_DB_URL", "postgresql://metadata")
    target = MySQLTarget(
        host="database.example.test",
        hostaddr="192.0.2.10",
        port=3306,
        database="records",
        username="reader",
        password="request-only-secret",
        tls_mode="required",
    )
    monkeypatch.setattr(scans, "resolve_mysql_target", lambda **_: target)
    submitted = []
    monkeypatch.setattr(
        scans, "submit_mysql_job", lambda **kwargs: submitted.append(kwargs)
    )
    principal = SimpleNamespace(
        database=_Database(), user=SimpleNamespace(id=uuid4())
    )
    request = BatchCreateRequest(
        label="mysql", targets=[_database_target()]
    )
    response = scans.create_batch(request, principal)
    assert response.jobs[0].status == "pending"
    assert submitted[0]["target"] == target

    monkeypatch.setattr(
        scans,
        "submit_mysql_job",
        lambda **_: (_ for _ in ()).throw(RuntimeError("executor stopped")),
    )
    principal = SimpleNamespace(
        database=_Database(), user=SimpleNamespace(id=uuid4())
    )
    response = scans.create_batch(request, principal)
    assert response.jobs[0].status == "failed"
    job = next(
        item for item in principal.database.items if isinstance(item, ScanJob)
    )
    assert job.error_code == "job_submit_failed"
    assert principal.database.commits == 2


def test_batch_status_derivation_and_lifespan_without_database(monkeypatch) -> None:
    assert scans._derive_batch_status([]) == "pending"
    assert scans._derive_batch_status(["cancelled"]) == "cancelled"
    assert scans._derive_batch_status(["failed"]) == "failed"
    assert scans._derive_batch_status(["pending", "running"]) == "running"
    assert scans._derive_batch_status(["completed", "failed"]) == (
        "completed_with_failures"
    )
    assert scans._derive_batch_status(["completed_with_warnings"]) == "completed"
    monkeypatch.delenv("APP_DB_URL", raising=False)
    app = create_app()

    async def run_lifespan():
        async with app.router.lifespan_context(app):
            pass

    asyncio.run(run_lifespan())
