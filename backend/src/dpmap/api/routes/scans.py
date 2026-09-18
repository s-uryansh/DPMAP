"""Scan creation, batch orchestration, and status routes."""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import os
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from dpmap.api.dependencies import AuthPrincipal, get_principal
from dpmap.api.errors import ApiError
from dpmap.api.schemas import (
    BatchCreateJobResponse,
    BatchCreateRequest,
    BatchCreateResponse,
    BatchJobStatusResponse,
    BatchStatusResponse,
    DirectoryScanRequest,
    DirectoryScanResponse,
    JobStatusResponse,
    MySQLScanRequest,
    PostgresScanRequest,
)
from dpmap.core.security import get_jwt_secret
from dpmap.db.models import AuditEvent, ScanBatch, ScanJob
from dpmap.engine.scanners.directory import (
    DirectoryScanError,
    configured_roots,
    validate_directory,
)
from dpmap.engine.scanners.postgres import (
    PostgresScanError,
    PostgresTarget,
    resolve_postgres_target,
)
from dpmap.engine.scanners.mysql import (
    MySQLScanError,
    MySQLTarget,
    resolve_mysql_target,
)
from dpmap.jobs.coordinator import (
    submit_directory_job,
    submit_mysql_job,
    submit_postgres_job,
)


router = APIRouter(prefix="/api/v1", tags=["scans"])


def _target_fingerprint(kind: str, target: str) -> str:
    return hmac.new(
        get_jwt_secret().encode(),
        f"{kind}\0{target}".encode(),
        sha256,
    ).hexdigest()


@dataclass(frozen=True)
class _PreparedJob:
    job: ScanJob
    client_ref: str
    target: Path | PostgresTarget | MySQLTarget | None
    detectors: frozenset[str]


def _detectors(names: list[str]) -> frozenset[str]:
    detectors = set(names)
    if "aadhaar" in detectors:
        detectors.add("aadhaar_masked")
    return frozenset(detectors)


def _failed_batch_job(
    *,
    batch_id: UUID,
    target_name: str,
    target_type: str,
    target_engine: str | None,
    target_display: str,
    target_fingerprint: str,
    detectors: frozenset[str],
    governance_context: dict[str, object],
    control_evidence: dict[str, object],
    error: DirectoryScanError | PostgresScanError | MySQLScanError,
) -> ScanJob:
    failed_at = datetime.now(timezone.utc)
    return ScanJob(
        id=uuid4(),
        batch_id=batch_id,
        target_name=target_name,
        target_type=target_type,
        target_engine=target_engine,
        target_display=target_display,
        target_fingerprint=target_fingerprint,
        detector_config_json={"detectors": sorted(detectors)},
        governance_context_json=governance_context,
        control_evidence_json=control_evidence,
        status="failed",
        stage="failed",
        coverage_status="failed",
        error_code=error.code,
        error_message=str(error),
        finished_at=failed_at,
        heartbeat_at=failed_at,
    )


def _prepare_batch_job(target, batch_id: UUID) -> _PreparedJob:
    detectors = _detectors(target.detectors)
    governance = target.governance_context
    evidence = target.control_evidence
    if target.type == "directory":
        display = os.path.abspath(target.directory.path)
        fingerprint = _target_fingerprint("directory", display)
        try:
            resource = validate_directory(
                target.directory.path,
                configured_roots(os.getenv("ALLOWED_SCAN_ROOTS")),
            )
        except DirectoryScanError as error:
            job = _failed_batch_job(
                batch_id=batch_id,
                target_name=target.target_name,
                target_type="directory",
                target_engine=None,
                target_display=display,
                target_fingerprint=fingerprint,
                detectors=detectors,
                governance_context=governance,
                control_evidence=evidence,
                error=error,
            )
            return _PreparedJob(job, target.client_ref, None, detectors)
        job = ScanJob(
            id=uuid4(),
            batch_id=batch_id,
            target_name=target.target_name,
            target_type="directory",
            target_engine=None,
            target_display=str(resource),
            target_fingerprint=_target_fingerprint("directory", str(resource)),
            detector_config_json={"detectors": sorted(detectors)},
            governance_context_json=governance,
            control_evidence_json=evidence,
        )
        return _PreparedJob(job, target.client_ref, resource, detectors)

    config = target.database
    display = f"{config.host}:{config.port}/{config.database}"
    if config.engine == "postgresql":
        try:
            resource = resolve_postgres_target(
                host=config.host,
                port=config.port,
                database=config.database,
                username=config.username,
                password=config.password.get_secret_value(),
                tls_mode=config.tls_mode,
                schemas=tuple(target.scope.schemas),
                allowed_hosts=os.getenv("ALLOWED_DB_HOSTS"),
                allow_insecure_tls=(
                    os.getenv("ALLOW_INSECURE_TARGET_TLS") == "true"
                ),
            )
        except PostgresScanError as error:
            fingerprint = _target_fingerprint("postgresql", display.lower())
            job = _failed_batch_job(
                batch_id=batch_id,
                target_name=target.target_name,
                target_type="database",
                target_engine="postgresql",
                target_display=display,
                target_fingerprint=fingerprint,
                detectors=detectors,
                governance_context=governance,
                control_evidence=evidence,
                error=error,
            )
            return _PreparedJob(job, target.client_ref, None, detectors)
        identity = f"{resource.hostaddr}:{resource.port}/{resource.database}"
        detector_config = {
            "detectors": sorted(detectors),
            "schemas": list(resource.schemas),
        }
    else:
        try:
            resource = resolve_mysql_target(
                host=config.host,
                port=config.port,
                database=config.database,
                username=config.username,
                password=config.password.get_secret_value(),
                tls_mode=config.tls_mode,
                ssl_ca=os.getenv("MYSQL_SSL_CA"),
                allowed_hosts=os.getenv("ALLOWED_DB_HOSTS"),
                allow_insecure_tls=(
                    os.getenv("ALLOW_INSECURE_TARGET_TLS") == "true"
                ),
            )
        except MySQLScanError as error:
            fingerprint = _target_fingerprint("mysql", display.lower())
            job = _failed_batch_job(
                batch_id=batch_id,
                target_name=target.target_name,
                target_type="database",
                target_engine="mysql",
                target_display=display,
                target_fingerprint=fingerprint,
                detectors=detectors,
                governance_context=governance,
                control_evidence=evidence,
                error=error,
            )
            return _PreparedJob(job, target.client_ref, None, detectors)
        identity = f"{resource.hostaddr}:{resource.port}/{resource.database}"
        detector_config = {"detectors": sorted(detectors)}

    job = ScanJob(
        id=uuid4(),
        batch_id=batch_id,
        target_name=target.target_name,
        target_type="database",
        target_engine=config.engine,
        target_display=display,
        target_fingerprint=_target_fingerprint(config.engine, identity),
        detector_config_json=detector_config,
        governance_context_json=governance,
        control_evidence_json=evidence,
    )
    return _PreparedJob(job, target.client_ref, resource, detectors)


def _job_status_fields(job: ScanJob) -> dict:
    return {
        "job_id": job.id,
        "status": job.status,
        "stage": job.stage,
        "progress_percent": job.progress_percent,
        "matches_found": job.matches_found,
        "units_scanned": job.units_scanned,
        "bytes_scanned": job.bytes_scanned,
        "locations_scanned": job.locations_scanned,
        "permission_check_status": job.permission_check_status,
        "coverage_status": job.coverage_status,
        "error_code": job.error_code,
        "error_message": job.error_message,
    }


def _derive_batch_status(statuses: list[str]) -> str:
    if not statuses:
        return "pending"
    if all(status == "cancelled" for status in statuses):
        return "cancelled"
    if all(status == "failed" for status in statuses):
        return "failed"
    terminal = {"completed", "completed_with_warnings", "failed", "cancelled"}
    if not all(status in terminal for status in statuses):
        return (
            "pending"
            if all(status == "pending" for status in statuses)
            else "running"
        )
    if any(status in {"failed", "cancelled"} for status in statuses):
        return "completed_with_failures"
    return "completed"


def _create_batch(
    request: BatchCreateRequest,
    principal: AuthPrincipal,
    *,
    reject_failed_preflight: bool = False,
) -> BatchCreateResponse:
    batch_id = uuid4()
    prepared = [
        _prepare_batch_job(target, batch_id) for target in request.targets
    ]
    if reject_failed_preflight and prepared[0].target is None:
        job = prepared[0].job
        raise ApiError(422, job.error_code, job.error_message)
    database = principal.database
    database.add_all(
        [
            ScanBatch(
                id=batch_id,
                label=request.label,
                created_by=principal.user.id,
            ),
            AuditEvent(
                id=uuid4(),
                actor_user_id=principal.user.id,
                action="batch.created",
                object_type="scan_batch",
                object_id=batch_id,
            ),
        ]
    )
    for item in prepared:
        database.add_all(
            [
                item.job,
                AuditEvent(
                    id=uuid4(),
                    actor_user_id=principal.user.id,
                    action="scan.created",
                    object_type="scan_job",
                    object_id=item.job.id,
                ),
            ]
        )
    try:
        database.commit()
    except IntegrityError as error:
        database.rollback()
        raise ApiError(
            409,
            "target_scan_active",
            "An active scan already exists for this target",
        ) from error

    database_url = os.environ["APP_DB_URL"]
    for item in prepared:
        if item.target is None:
            continue
        try:
            if isinstance(item.target, Path):
                submit_directory_job(
                    job_id=item.job.id,
                    root=item.target,
                    detectors=item.detectors,
                    database_url=database_url,
                )
            elif isinstance(item.target, PostgresTarget):
                submit_postgres_job(
                    job_id=item.job.id,
                    target=item.target,
                    detectors=item.detectors,
                    database_url=database_url,
                )
            else:
                submit_mysql_job(
                    job_id=item.job.id,
                    target=item.target,
                    detectors=item.detectors,
                    database_url=database_url,
                )
        except Exception:
            item.job.status = "failed"
            item.job.stage = "failed"
            item.job.coverage_status = "failed"
            item.job.error_code = "job_submit_failed"
            item.job.error_message = "Scan job could not be submitted"
            item.job.finished_at = datetime.now(timezone.utc)
            item.job.heartbeat_at = item.job.finished_at
            database.commit()

    return BatchCreateResponse(
        batch_id=batch_id,
        jobs=[
            BatchCreateJobResponse(
                job_id=item.job.id,
                client_ref=item.client_ref,
                status=item.job.status,
                status_url=f"/api/v1/jobs/{item.job.id}/status",
            )
            for item in prepared
        ],
        batch_status_url=f"/api/v1/batches/{batch_id}/status",
    )


@router.post("/batches", status_code=202)
def create_batch(
    request: BatchCreateRequest,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> BatchCreateResponse:
    return _create_batch(request, principal)


@router.post("/scans/directory", status_code=202)
def create_directory_scan(
    request: DirectoryScanRequest,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> DirectoryScanResponse:
    batch = _create_batch(
        BatchCreateRequest(
            label=request.label,
            targets=[
                {
                    "client_ref": "target",
                    "target_name": request.target_name,
                    "type": "directory",
                    "directory": {"path": request.path},
                    "detectors": request.detectors,
                }
            ],
        ),
        principal,
        reject_failed_preflight=True,
    )
    job = batch.jobs[0]
    return DirectoryScanResponse(
        batch_id=batch.batch_id,
        job_id=job.job_id,
        status=job.status,
        status_url=job.status_url,
    )


@router.post("/scans/postgres", status_code=202)
def create_postgres_scan(
    request: PostgresScanRequest,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> DirectoryScanResponse:
    batch = _create_batch(
        BatchCreateRequest(
            label=request.label,
            targets=[
                {
                    "client_ref": "target",
                    "target_name": request.target_name,
                    "type": "database",
                    "database": {
                        "engine": "postgresql",
                        "host": request.host,
                        "port": request.port,
                        "database": request.database,
                        "username": request.username,
                        "password": request.password,
                        "tls_mode": request.tls_mode,
                    },
                    "scope": {"schemas": request.schemas},
                    "detectors": request.detectors,
                }
            ],
        ),
        principal,
        reject_failed_preflight=True,
    )
    job = batch.jobs[0]
    return DirectoryScanResponse(
        batch_id=batch.batch_id,
        job_id=job.job_id,
        status=job.status,
        status_url=job.status_url,
    )


@router.post("/scans/mysql", status_code=202)
def create_mysql_scan(
    request: MySQLScanRequest,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> DirectoryScanResponse:
    batch = _create_batch(
        BatchCreateRequest(
            label=request.label,
            targets=[
                {
                    "client_ref": "target",
                    "target_name": request.target_name,
                    "type": "database",
                    "database": {
                        "engine": "mysql",
                        "host": request.host,
                        "port": request.port,
                        "database": request.database,
                        "username": request.username,
                        "password": request.password,
                        "tls_mode": request.tls_mode,
                    },
                    "detectors": request.detectors,
                }
            ],
        ),
        principal,
        reject_failed_preflight=True,
    )
    job = batch.jobs[0]
    return DirectoryScanResponse(
        batch_id=batch.batch_id,
        job_id=job.job_id,
        status=job.status,
        status_url=job.status_url,
    )


@router.get("/jobs/{job_id}/status")
def get_job_status(
    job_id: UUID,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> JobStatusResponse:
    job = principal.database.get(ScanJob, job_id)
    if job is None:
        raise ApiError(404, "job_not_found", "Scan job not found")
    return JobStatusResponse(**_job_status_fields(job))


@router.get("/batches/{batch_id}/status")
def get_batch_status(
    batch_id: UUID,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> BatchStatusResponse:
    batch = principal.database.get(ScanBatch, batch_id)
    if batch is None:
        raise ApiError(404, "batch_not_found", "Scan batch not found")
    jobs = principal.database.scalars(
        select(ScanJob)
        .where(ScanJob.batch_id == batch_id)
        .order_by(ScanJob.created_at, ScanJob.id)
    ).all()
    return BatchStatusResponse(
        batch_id=batch_id,
        status=_derive_batch_status([job.status for job in jobs]),
        jobs=[
            BatchJobStatusResponse(
                **_job_status_fields(job),
                target_name=job.target_name,
                target_type=job.target_type,
                target_engine=job.target_engine,
            )
            for job in jobs
        ],
    )
