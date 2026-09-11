"""SQLAlchemy models for aggregate metadata only.

Matched PII values, source excerpts, hashes of values, and target credentials must
never cross into these tables. Location locators are plain text in v1 and depend on
application RBAC and PostgreSQL access controls; they are not column-level encrypted.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}
EMPTY_JSON = text("'{}'::jsonb")
ZERO = text("0")


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("email = lower(email)", name="email_normalized"),
        CheckConstraint("role IN ('admin', 'auditor')", name="role_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    email: Mapped[str] = mapped_column(Text, unique=True)
    role: Mapped[str] = mapped_column(String(16))
    password_hash: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("true"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    __table_args__ = (
        CheckConstraint("expires_at > created_at", name="expiry_after_creation"),
        CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name="revocation_after_creation",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ScanBatch(Base):
    __tablename__ = "scan_batches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    label: Mapped[str] = mapped_column(Text)
    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint(
            "target_type IN ('database', 'directory')", name="target_type_valid"
        ),
        CheckConstraint(
            "(target_type = 'database' AND target_engine IN "
            "('postgresql', 'mysql')) OR "
            "(target_type = 'directory' AND target_engine IS NULL)",
            name="target_engine_matches_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'validating', 'running', 'completed', "
            "'completed_with_warnings', 'failed', 'cancelled')",
            name="status_valid",
        ),
        CheckConstraint(
            "progress_percent BETWEEN 0 AND 100", name="progress_range"
        ),
        CheckConstraint(
            "(status IN ('completed', 'completed_with_warnings', 'failed', "
            "'cancelled') AND finished_at IS NOT NULL) OR "
            "(status NOT IN ('completed', 'completed_with_warnings', 'failed', "
            "'cancelled') AND finished_at IS NULL)",
            name="terminal_has_finished_at",
        ),
        CheckConstraint(
            "status NOT IN ('completed', 'completed_with_warnings') "
            "OR progress_percent = 100",
            name="completed_has_full_progress",
        ),
        CheckConstraint(
            "error_code IS NULL OR status IN ('failed', 'completed_with_warnings')",
            name="error_code_matches_status",
        ),
        CheckConstraint(
            "error_message IS NULL OR status IN "
            "('failed', 'completed_with_warnings')",
            name="error_message_matches_status",
        ),
        CheckConstraint(
            "matches_found >= 0 AND units_scanned >= 0 AND bytes_scanned >= 0 "
            "AND locations_scanned >= 0",
            name="metrics_nonnegative",
        ),
        CheckConstraint(
            "permission_check_status IN ('pending', 'verified_limited', "
            "'overprivileged', 'unverifiable', 'not_applicable')",
            name="permission_status_valid",
        ),
        CheckConstraint(
            "coverage_status IN ('pending', 'complete', 'partial', 'failed', "
            "'unassessed')",
            name="coverage_status_valid",
        ),
        CheckConstraint("length(target_fingerprint) = 64", name="fingerprint_length"),
        Index(
            "uq_scan_jobs_active_target",
            "target_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('pending', 'validating', 'running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    batch_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_batches.id", ondelete="CASCADE"), index=True
    )
    target_name: Mapped[str] = mapped_column(Text)
    target_type: Mapped[str] = mapped_column(String(16))
    target_engine: Mapped[str | None] = mapped_column(String(16))
    target_display: Mapped[str] = mapped_column(
        Text,
        comment="Plain text in v1; protected by RBAC and database access controls only",
    )
    target_fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), server_default=text("'pending'"))
    stage: Mapped[str | None] = mapped_column(String(64))
    progress_percent: Mapped[int] = mapped_column(Integer, server_default=ZERO)
    matches_found: Mapped[int] = mapped_column(BigInteger, server_default=ZERO)
    units_scanned: Mapped[int] = mapped_column(BigInteger, server_default=ZERO)
    bytes_scanned: Mapped[int] = mapped_column(BigInteger, server_default=ZERO)
    locations_scanned: Mapped[int] = mapped_column(BigInteger, server_default=ZERO)
    detector_config_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=EMPTY_JSON
    )
    governance_context_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=EMPTY_JSON
    )
    control_evidence_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=EMPTY_JSON
    )
    permission_check_status: Mapped[str] = mapped_column(
        String(32), server_default=text("'pending'")
    )
    coverage_status: Mapped[str] = mapped_column(
        String(16), server_default=text("'pending'")
    )
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanInventoryItem(Base):
    __tablename__ = "scan_inventory_items"
    __table_args__ = (
        CheckConstraint("length(location_locator) > 0", name="locator_not_empty"),
        CheckConstraint(
            "field_locator IS NULL OR length(field_locator) > 0",
            name="field_locator_not_empty",
        ),
        CheckConstraint(
            "match_count >= 0 AND units_with_pii >= 0 AND units_scanned >= 0 "
            "AND bytes_scanned >= 0",
            name="metrics_nonnegative",
        ),
        CheckConstraint(
            "units_with_pii <= units_scanned", name="pii_units_within_scanned"
        ),
        CheckConstraint(
            "confidence_band IN ('low', 'medium', 'high', 'unassessed')",
            name="confidence_valid",
        ),
        CheckConstraint(
            "coverage_status IN ('complete', 'partial', 'failed', 'unassessed')",
            name="coverage_status_valid",
        ),
        Index(
            "uq_inventory_item_identity",
            "job_id",
            "location_locator",
            text("COALESCE(field_locator, '')"),
            "pii_type",
            "detector_version",
            unique=True,
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    location_kind: Mapped[str] = mapped_column(String(16))
    location_locator: Mapped[str] = mapped_column(
        Text,
        comment="Plain text in v1; not column-level encrypted or pseudonymized",
    )
    field_locator: Mapped[str | None] = mapped_column(Text)
    pii_type: Mapped[str] = mapped_column(String(64))
    match_count: Mapped[int] = mapped_column(BigInteger)
    units_with_pii: Mapped[int] = mapped_column(BigInteger)
    units_scanned: Mapped[int] = mapped_column(BigInteger)
    bytes_scanned: Mapped[int] = mapped_column(BigInteger)
    confidence_band: Mapped[str] = mapped_column(String(16))
    detector_version: Mapped[str] = mapped_column(String(64))
    coverage_status: Mapped[str] = mapped_column(String(16))
    warnings_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=EMPTY_JSON
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RemediationItem(Base):
    __tablename__ = "remediation_items"
    __table_args__ = (
        CheckConstraint("risk_score >= 0", name="risk_score_nonnegative"),
        CheckConstraint(
            "risk_band IN ('red', 'amber', 'green', 'grey')",
            name="risk_band_valid",
        ),
        CheckConstraint(
            "evidence_state IN ('observed', 'operator_attested', 'unknown')",
            name="evidence_state_valid",
        ),
        CheckConstraint(
            "control_state IN ('present', 'absent', 'partial', 'not_applicable', "
            "'unknown')",
            name="control_state_valid",
        ),
        CheckConstraint(
            "status IN ('open', 'accepted', 'resolved', 'risk_accepted')",
            name="status_valid",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True
    )
    inventory_item_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_inventory_items.id", ondelete="SET NULL"), index=True
    )
    rule_id: Mapped[str] = mapped_column(String(64))
    rule_version: Mapped[str] = mapped_column(String(64))
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_band: Mapped[str] = mapped_column(String(16))
    reason_codes_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=EMPTY_JSON
    )
    evidence_state: Mapped[str] = mapped_column(String(24))
    control_state: Mapped[str] = mapped_column(String(24))
    recommended_control: Mapped[str] = mapped_column(Text)
    suggested_owner: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), server_default=text("'open'"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ScanReport(Base):
    __tablename__ = "scan_reports"
    __table_args__ = (
        CheckConstraint(
            "total_matches >= 0 AND units_with_pii >= 0 AND high_risk_flags >= 0",
            name="totals_nonnegative",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), unique=True
    )
    total_matches: Mapped[int] = mapped_column(BigInteger, server_default=ZERO)
    units_with_pii: Mapped[int] = mapped_column(BigInteger, server_default=ZERO)
    high_risk_flags: Mapped[int] = mapped_column(BigInteger, server_default=ZERO)
    report_schema_version: Mapped[str] = mapped_column(String(64))
    report_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=EMPTY_JSON
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(64))
    object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=EMPTY_JSON
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
