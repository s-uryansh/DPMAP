import json
import os
from pathlib import Path
import resource
from types import SimpleNamespace
import secrets
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from openpyxl import Workbook
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from dpmap.core.security import encode_access_token, hash_password
from dpmap.db.models import AuditEvent, AuthSession, ScanInventoryItem, ScanJob, User
from dpmap.db.session import _session_factory
from dpmap.jobs.coordinator import _fail_job, _run_directory_job
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
        response = request(
            app, "GET", f"/api/v1/jobs/{job_id}/status", token=token
        )
        if response[1]["status"] in {
            "completed",
            "completed_with_warnings",
            "failed",
        }:
            return response
        time.sleep(0.05)
    raise AssertionError("directory scan did not finish")


def test_directory_job_api_streams_files_and_persists_only_aggregates(
    tmp_path, monkeypatch
) -> None:
    database_url = os.getenv("TEST_APP_DB_URL")
    if not database_url:
        pytest.skip("TEST_APP_DB_URL is required for directory integration tests")

    root = tmp_path / "allowed"
    root.mkdir()
    (root / "records.txt").write_text("Contact audit@example.in")
    (root / "records.csv").write_text(
        "pan,mobile\nABCDE1234F,9876543210\n", encoding="utf-8"
    )
    workbook = Workbook()
    workbook.active.append(["Aadhaar", "9999 9999 0019"])
    workbook.save(root / "records.xlsx")
    workbook.close()
    (root / "large.txt").write_text("x" * (5 * 1024 * 1024) + " end@example.in")
    denied = root / "denied.txt"
    denied.write_text("PAN ABCDE1234F")
    unstable = root / "unstable.txt"
    unstable.write_text("nothing sensitive")
    (root / ".hidden.txt").write_text("hidden@example.in")
    (root / "ignored.pdf").write_bytes(b"not scanned")
    (root / "broken.xlsx").write_bytes(b"not a zip archive")
    (root / "linked.txt").symlink_to(root / "records.txt")

    original_open = Path.open
    original_stat = Path.stat
    unstable_stats = 0

    def controlled_open(path, *args, **kwargs):
        if path == denied:
            raise PermissionError
        return original_open(path, *args, **kwargs)

    def controlled_stat(path, *args, **kwargs):
        nonlocal unstable_stats
        value = original_stat(path, *args, **kwargs)
        if path != unstable:
            return value
        unstable_stats += 1
        if unstable_stats < 2:
            return value
        return SimpleNamespace(
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns + 1,
        )

    monkeypatch.setattr(Path, "open", controlled_open)
    monkeypatch.setattr(Path, "stat", controlled_stat)
    jwt_secret = secrets.token_urlsafe(48)
    monkeypatch.setenv("JWT_SECRET", jwt_secret)
    monkeypatch.setenv("APP_DB_URL", database_url)
    monkeypatch.setenv("ALLOWED_SCAN_ROOTS", str(root))

    config = _alembic_config(database_url)
    engine = create_engine(database_url)
    session_factory = sessionmaker(engine, expire_on_commit=False)
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    now = datetime.now(timezone.utc)
    user_id = uuid4()
    jti = uuid4()
    with session_factory() as database:
        database.add(
            User(
                id=user_id,
                email="scanner@example.test",
                role="admin",
                password_hash=hash_password("directory-test-password"),
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
    before_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    try:
        created = request(
            app,
            "POST",
            "/api/v1/scans/directory",
            {
                "label": "Directory test",
                "target_name": "Synthetic files",
                "path": str(root),
                "detectors": ["pan", "aadhaar", "phone", "email"],
            },
            token,
        )
        assert created[0] == 202
        status = _wait_for_terminal(app, created[1]["job_id"], token)
        assert status[0] == 200
        assert status[1]["status"] == "completed_with_warnings"
        assert status[1]["coverage_status"] == "partial"
        assert status[1]["progress_percent"] == 100
        assert status[1]["matches_found"] == 5
        assert status[1]["locations_scanned"] == 5
        assert status[1]["bytes_scanned"] >= 5 * 1024 * 1024
        after_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        assert after_rss - before_rss < 128 * 1024

        with session_factory() as database:
            job = database.get(ScanJob, created[1]["job_id"])
            items = list(
                database.scalars(
                    select(ScanInventoryItem).where(
                        ScanInventoryItem.job_id == job.id
                    )
                )
            )
            assert sum(item.match_count for item in items) == 5
            persisted = json.dumps(
                [
                    {
                        "locator": item.location_locator,
                        "field": item.field_locator,
                        "warnings": item.warnings_json,
                    }
                    for item in items
                ]
            )
            for value in (
                "audit@example.in",
                "ABCDE1234F",
                "9876543210",
                "9999 9999 0019",
                "end@example.in",
            ):
                assert value not in persisted
            assert database.scalar(
                select(AuditEvent).where(AuditEvent.action == "scan.created")
            )

        outside = request(
            app,
            "POST",
            "/api/v1/scans/directory",
            {
                "label": "Outside",
                "target_name": "Outside",
                "path": str(tmp_path),
                "detectors": ["email"],
            },
            token,
        )
        assert outside[0] == 422
        assert outside[1]["code"] == "path_not_allowed"
        assert request(app, "GET", f"/api/v1/jobs/{uuid4()}/status", token=token)[
            0
        ] == 404

        clean = root / "clean"
        clean.mkdir()
        (clean / "empty.txt").write_text("no findings")
        clean_created = request(
            app,
            "POST",
            "/api/v1/scans/directory",
            {
                "label": "Clean",
                "target_name": "Clean",
                "path": str(clean),
                "detectors": ["email"],
            },
            token,
        )
        clean_status = _wait_for_terminal(
            app, clean_created[1]["job_id"], token
        )
        assert clean_status[1]["status"] == "completed"
        assert clean_status[1]["coverage_status"] == "complete"

        failed = root / "failed"
        failed.mkdir()
        with monkeypatch.context() as patch:
            patch.setattr(
                "dpmap.jobs.coordinator.scan_directory",
                lambda *_: (_ for _ in ()).throw(RuntimeError()),
            )
            failed_created = request(
                app,
                "POST",
                "/api/v1/scans/directory",
                {
                    "label": "Failed",
                    "target_name": "Failed",
                    "path": str(failed),
                    "detectors": ["email"],
                },
                token,
            )
            failed_status = _wait_for_terminal(
                app, failed_created[1]["job_id"], token
            )
        assert failed_status[1]["status"] == "failed"
        assert failed_status[1]["error_code"] == "scan_failed"

        _run_directory_job(uuid4(), root, frozenset({"email"}), database_url)
        _fail_job(database_url, uuid4())

        active = root / "active"
        active.mkdir()
        with monkeypatch.context() as patch:
            patch.setattr(
                "dpmap.api.routes.scans.submit_directory_job", lambda **_: None
            )
            payload = {
                "label": "Active",
                "target_name": "Active",
                "path": str(active),
                "detectors": ["email"],
            }
            assert request(
                app, "POST", "/api/v1/scans/directory", payload, token
            )[0] == 202
            conflict = request(
                app, "POST", "/api/v1/scans/directory", payload, token
            )
        assert conflict[0] == 409
        assert conflict[1]["code"] == "target_scan_active"
    finally:
        _session_factory.cache_clear()
        command.downgrade(config, "base")
        engine.dispose()
