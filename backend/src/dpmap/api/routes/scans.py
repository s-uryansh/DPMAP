"""Directory scan creation and status routes."""

from hashlib import sha256
import hmac
import os
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends
from sqlalchemy.exc import IntegrityError

from dpmap.api.dependencies import AuthPrincipal, get_principal
from dpmap.api.errors import ApiError
from dpmap.api.schemas import (
    DirectoryScanRequest,
    DirectoryScanResponse,
    JobStatusResponse,
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
    resolve_postgres_target,
)
from dpmap.jobs.coordinator import submit_directory_job, submit_postgres_job


router = APIRouter(prefix="/api/v1", tags=["scans"])


def _target_fingerprint(kind: str, target: str) -> str:
    return hmac.new(
        get_jwt_secret().encode(),
        f"{kind}\0{target}".encode(),
        sha256,
    ).hexdigest()


@router.post("/scans/directory", status_code=202)
def create_directory_scan(
    request: DirectoryScanRequest,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> DirectoryScanResponse:
    try:
        roots = configured_roots(os.getenv("ALLOWED_SCAN_ROOTS"))
        target = validate_directory(request.path, roots)
    except DirectoryScanError as error:
        raise ApiError(422, error.code, str(error)) from error

    batch_id = uuid4()
    job_id = uuid4()
    database = principal.database
    database_url = os.environ["APP_DB_URL"]
    detectors = set(request.detectors)
    if "aadhaar" in detectors:
        detectors.add("aadhaar_masked")
    batch = ScanBatch(
        id=batch_id,
        label=request.label,
        created_by=principal.user.id,
    )
    job = ScanJob(
        id=job_id,
        batch_id=batch_id,
        target_name=request.target_name,
        target_type="directory",
        target_engine=None,
        target_display=str(target),
        target_fingerprint=_target_fingerprint("directory", str(target)),
        detector_config_json={"detectors": sorted(detectors)},
    )
    database.add_all(
        [
            batch,
            job,
            AuditEvent(
                id=uuid4(),
                actor_user_id=principal.user.id,
                action="scan.created",
                object_type="scan_job",
                object_id=job_id,
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

    submit_directory_job(
        job_id=job_id,
        root=target,
        detectors=frozenset(detectors),
        database_url=database_url,
    )
    return DirectoryScanResponse(
        batch_id=batch_id,
        job_id=job_id,
        status="pending",
        status_url=f"/api/v1/jobs/{job_id}/status",
    )


@router.post("/scans/postgres", status_code=202)
def create_postgres_scan(
    request: PostgresScanRequest,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> DirectoryScanResponse:
    try:
        target = resolve_postgres_target(
            host=request.host,
            port=request.port,
            database=request.database,
            username=request.username,
            password=request.password.get_secret_value(),
            tls_mode=request.tls_mode,
            schemas=tuple(request.schemas),
            allowed_hosts=os.getenv("ALLOWED_DB_HOSTS"),
            allow_insecure_tls=os.getenv("ALLOW_INSECURE_TARGET_TLS") == "true",
        )
    except PostgresScanError as error:
        raise ApiError(422, error.code, str(error)) from error

    batch_id = uuid4()
    job_id = uuid4()
    database = principal.database
    database_url = os.environ["APP_DB_URL"]
    detectors = set(request.detectors)
    if "aadhaar" in detectors:
        detectors.add("aadhaar_masked")
    target_identity = f"{target.hostaddr}:{target.port}/{target.database}"
    database.add_all(
        [
            ScanBatch(
                id=batch_id,
                label=request.label,
                created_by=principal.user.id,
            ),
            ScanJob(
                id=job_id,
                batch_id=batch_id,
                target_name=request.target_name,
                target_type="database",
                target_engine="postgresql",
                target_display=f"{target.host}:{target.port}/{target.database}",
                target_fingerprint=_target_fingerprint(
                    "postgresql", target_identity
                ),
                detector_config_json={
                    "detectors": sorted(detectors),
                    "schemas": list(target.schemas),
                },
            ),
            AuditEvent(
                id=uuid4(),
                actor_user_id=principal.user.id,
                action="scan.created",
                object_type="scan_job",
                object_id=job_id,
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

    submit_postgres_job(
        job_id=job_id,
        target=target,
        detectors=frozenset(detectors),
        database_url=database_url,
    )
    return DirectoryScanResponse(
        batch_id=batch_id,
        job_id=job_id,
        status="pending",
        status_url=f"/api/v1/jobs/{job_id}/status",
    )


@router.get("/jobs/{job_id}/status")
def get_job_status(
    job_id: UUID,
    principal: Annotated[AuthPrincipal, Depends(get_principal)],
) -> JobStatusResponse:
    job = principal.database.get(ScanJob, job_id)
    if job is None:
        raise ApiError(404, "job_not_found", "Scan job not found")
    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        stage=job.stage,
        progress_percent=job.progress_percent,
        matches_found=job.matches_found,
        units_scanned=job.units_scanned,
        bytes_scanned=job.bytes_scanned,
        locations_scanned=job.locations_scanned,
        permission_check_status=job.permission_check_status,
        coverage_status=job.coverage_status,
        error_code=job.error_code,
        error_message=job.error_message,
    )
