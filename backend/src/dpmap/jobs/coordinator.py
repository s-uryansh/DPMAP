"""Bounded in-process coordinator for directory jobs."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from dpmap.db.models import ScanInventoryItem, ScanJob
from dpmap.db.session import _session_factory
from dpmap.engine.detectors.pipeline import DETECTOR_VERSION
from dpmap.engine.scanners.directory import scan_directory
from dpmap.engine.scanners.postgres import (
    DatabaseColumnResult,
    PostgresScanError,
    PostgresTarget,
    scan_postgres,
)


# ponytail: single-process pool; use secret-referenced workers when HA is required.
_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dpmap-scan")
_DATABASE_TARGETS: dict[UUID, PostgresTarget] = {}
_DATABASE_TARGETS_LOCK = Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def submit_directory_job(
    *,
    job_id: UUID,
    root: Path,
    detectors: frozenset[str],
    database_url: str,
) -> None:
    _EXECUTOR.submit(_run_directory_job, job_id, root, detectors, database_url)


def _fail_job(
    database_url: str,
    job_id: UUID,
    *,
    code: str = "scan_failed",
    message: str = "Directory scan failed",
) -> None:
    with _session_factory(database_url)() as database:
        job = database.get(ScanJob, job_id)
        if job is None:
            return
        job.status = "failed"
        job.stage = "failed"
        job.coverage_status = "failed"
        job.error_code = code
        job.error_message = message
        job.finished_at = _now()
        job.heartbeat_at = job.finished_at
        database.commit()


def _persist_result(
    database: Session, job: ScanJob, result, warning_count: int
) -> int:
    if result.scanned:
        job.locations_scanned += 1
        job.units_scanned += result.units_scanned
        job.bytes_scanned += result.bytes_scanned
    warning_count += len(result.warnings)
    for item in result.items:
        job.matches_found += item.match_count
        database.add(
            ScanInventoryItem(
                id=uuid4(),
                job_id=job.id,
                location_kind="file",
                location_locator=str(result.path),
                field_locator=item.field_locator,
                pii_type=item.pii_type,
                match_count=item.match_count,
                units_with_pii=item.units_with_pii,
                units_scanned=item.units_scanned,
                bytes_scanned=result.bytes_scanned,
                confidence_band=item.confidence_band,
                detector_version=DETECTOR_VERSION,
                coverage_status="partial" if result.warnings else "complete",
                warnings_json={
                    "reason_codes": list(item.reason_codes),
                    "warnings": list(result.warnings),
                },
            )
        )
    job.progress_percent = min(95, job.progress_percent + 1)
    job.heartbeat_at = _now()
    database.commit()
    return warning_count


def _run_directory_job(
    job_id: UUID,
    root: Path,
    detectors: frozenset[str],
    database_url: str,
) -> None:
    try:
        with _session_factory(database_url)() as database:
            job = database.get(ScanJob, job_id)
            if job is None:
                return
            job.status = "running"
            job.stage = "scanning"
            job.progress_percent = 5
            job.started_at = _now()
            job.heartbeat_at = job.started_at
            database.commit()

            warning_count = 0
            for result in scan_directory(root, detectors):
                warning_count = _persist_result(
                    database, job, result, warning_count
                )

            finished = _now()
            job.status = (
                "completed_with_warnings" if warning_count else "completed"
            )
            job.stage = "completed"
            job.progress_percent = 100
            job.permission_check_status = "not_applicable"
            job.coverage_status = "partial" if warning_count else "complete"
            job.error_code = "partial_coverage" if warning_count else None
            job.error_message = (
                f"{warning_count} scan warnings recorded"
                if warning_count
                else None
            )
            job.finished_at = finished
            job.heartbeat_at = finished
            database.commit()
    except Exception:
        _fail_job(database_url, job_id)


def submit_postgres_job(
    *,
    job_id: UUID,
    target: PostgresTarget,
    detectors: frozenset[str],
    database_url: str,
) -> None:
    with _DATABASE_TARGETS_LOCK:
        _DATABASE_TARGETS[job_id] = target
    try:
        _EXECUTOR.submit(_run_postgres_job, job_id, detectors, database_url)
    except Exception:
        with _DATABASE_TARGETS_LOCK:
            _DATABASE_TARGETS.pop(job_id, None)
        raise


def _persist_database_result(
    database: Session, job: ScanJob, result: DatabaseColumnResult
) -> None:
    job.locations_scanned += 1
    job.units_scanned += result.units_scanned
    job.bytes_scanned += result.bytes_scanned
    for item in result.items:
        job.matches_found += item.match_count
        database.add(
            ScanInventoryItem(
                id=uuid4(),
                job_id=job.id,
                location_kind="table",
                location_locator=result.location_locator,
                field_locator=item.field_locator,
                pii_type=item.pii_type,
                match_count=item.match_count,
                units_with_pii=item.units_with_pii,
                units_scanned=item.units_scanned,
                bytes_scanned=result.bytes_scanned,
                confidence_band=item.confidence_band,
                detector_version=DETECTOR_VERSION,
                coverage_status="complete",
                warnings_json={"reason_codes": list(item.reason_codes)},
            )
        )
    job.progress_percent = min(95, job.progress_percent + 1)
    job.heartbeat_at = _now()
    database.commit()


def _run_postgres_job(
    job_id: UUID, detectors: frozenset[str], database_url: str
) -> None:
    with _DATABASE_TARGETS_LOCK:
        target = _DATABASE_TARGETS.get(job_id)
    if target is None:
        return
    try:
        with _session_factory(database_url)() as database:
            job = database.get(ScanJob, job_id)
            if job is None:
                return
            job.status = "running"
            job.stage = "scanning"
            job.progress_percent = 5
            job.started_at = _now()
            job.heartbeat_at = job.started_at
            database.commit()

            permission, unsupported = scan_postgres(
                target,
                detectors,
                lambda result: _persist_database_result(database, job, result),
            )
            warnings = unsupported + (target.tls_mode != "verify-full") + (
                permission != "verified_limited"
            )
            finished = _now()
            job.status = "completed_with_warnings" if warnings else "completed"
            job.stage = "completed"
            job.progress_percent = 100
            job.permission_check_status = permission
            job.coverage_status = "partial" if unsupported else "complete"
            job.error_code = "scan_warnings" if warnings else None
            job.error_message = (
                f"{warnings} scan warnings recorded" if warnings else None
            )
            job.finished_at = finished
            job.heartbeat_at = finished
            database.commit()
    except PostgresScanError as error:
        _fail_job(
            database_url,
            job_id,
            code=error.code,
            message=str(error),
        )
    except Exception:
        _fail_job(
            database_url,
            job_id,
            code="target_scan_failed",
            message="Target database scan failed",
        )
    finally:
        with _DATABASE_TARGETS_LOCK:
            _DATABASE_TARGETS.pop(job_id, None)
