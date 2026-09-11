"""create_metadata_schema

Revision ID: 58250c8a9246
Revises: 
Create Date: 2026-09-11 10:19:05.944094
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = '58250c8a9246'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('users',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('email', sa.Text(), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=False),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("role IN ('admin', 'auditor')", name=op.f('ck_users_role_valid')),
    sa.CheckConstraint('email = lower(email)', name=op.f('ck_users_email_normalized')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_users')),
    sa.UniqueConstraint('email', name=op.f('uq_users_email'))
    )
    op.create_table('audit_events',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('actor_user_id', sa.UUID(), nullable=True),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('object_type', sa.String(length=64), nullable=False),
    sa.Column('object_id', sa.UUID(), nullable=True),
    sa.Column('details_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], name=op.f('fk_audit_events_actor_user_id_users'), ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_events'))
    )
    op.create_index(op.f('ix_audit_events_actor_user_id'), 'audit_events', ['actor_user_id'], unique=False)
    op.create_index(op.f('ix_audit_events_created_at'), 'audit_events', ['created_at'], unique=False)
    op.create_table('auth_sessions',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('expires_at > created_at', name=op.f('ck_auth_sessions_expiry_after_creation')),
    sa.CheckConstraint('revoked_at IS NULL OR revoked_at >= created_at', name=op.f('ck_auth_sessions_revocation_after_creation')),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_auth_sessions_user_id_users'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_auth_sessions'))
    )
    op.create_index(op.f('ix_auth_sessions_user_id'), 'auth_sessions', ['user_id'], unique=False)
    op.create_table('scan_batches',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('label', sa.Text(), nullable=False),
    sa.Column('created_by', sa.UUID(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_scan_batches_created_by_users'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan_batches'))
    )
    op.create_index(op.f('ix_scan_batches_created_by'), 'scan_batches', ['created_by'], unique=False)
    op.create_table('scan_jobs',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('batch_id', sa.UUID(), nullable=False),
    sa.Column('target_name', sa.Text(), nullable=False),
    sa.Column('target_type', sa.String(length=16), nullable=False),
    sa.Column('target_engine', sa.String(length=16), nullable=True),
    sa.Column('target_display', sa.Text(), nullable=False, comment='Plain text in v1; protected by RBAC and database access controls only'),
    sa.Column('target_fingerprint', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=32), server_default=sa.text("'pending'"), nullable=False),
    sa.Column('stage', sa.String(length=64), nullable=True),
    sa.Column('progress_percent', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('matches_found', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('units_scanned', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('bytes_scanned', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('locations_scanned', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('detector_config_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('governance_context_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('control_evidence_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('permission_check_status', sa.String(length=32), server_default=sa.text("'pending'"), nullable=False),
    sa.Column('coverage_status', sa.String(length=16), server_default=sa.text("'pending'"), nullable=False),
    sa.Column('error_code', sa.String(length=64), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint("(status IN ('completed', 'completed_with_warnings', 'failed', 'cancelled') AND finished_at IS NOT NULL) OR (status NOT IN ('completed', 'completed_with_warnings', 'failed', 'cancelled') AND finished_at IS NULL)", name=op.f('ck_scan_jobs_terminal_has_finished_at')),
    sa.CheckConstraint("(target_type = 'database' AND target_engine IN ('postgresql', 'mysql')) OR (target_type = 'directory' AND target_engine IS NULL)", name=op.f('ck_scan_jobs_target_engine_matches_type')),
    sa.CheckConstraint("coverage_status IN ('pending', 'complete', 'partial', 'failed', 'unassessed')", name=op.f('ck_scan_jobs_coverage_status_valid')),
    sa.CheckConstraint("error_code IS NULL OR status IN ('failed', 'completed_with_warnings')", name=op.f('ck_scan_jobs_error_code_matches_status')),
    sa.CheckConstraint("error_message IS NULL OR status IN ('failed', 'completed_with_warnings')", name=op.f('ck_scan_jobs_error_message_matches_status')),
    sa.CheckConstraint("permission_check_status IN ('pending', 'verified_limited', 'overprivileged', 'unverifiable', 'not_applicable')", name=op.f('ck_scan_jobs_permission_status_valid')),
    sa.CheckConstraint("status IN ('pending', 'validating', 'running', 'completed', 'completed_with_warnings', 'failed', 'cancelled')", name=op.f('ck_scan_jobs_status_valid')),
    sa.CheckConstraint("status NOT IN ('completed', 'completed_with_warnings') OR progress_percent = 100", name=op.f('ck_scan_jobs_completed_has_full_progress')),
    sa.CheckConstraint("target_type IN ('database', 'directory')", name=op.f('ck_scan_jobs_target_type_valid')),
    sa.CheckConstraint('length(target_fingerprint) = 64', name=op.f('ck_scan_jobs_fingerprint_length')),
    sa.CheckConstraint('matches_found >= 0 AND units_scanned >= 0 AND bytes_scanned >= 0 AND locations_scanned >= 0', name=op.f('ck_scan_jobs_metrics_nonnegative')),
    sa.CheckConstraint('progress_percent BETWEEN 0 AND 100', name=op.f('ck_scan_jobs_progress_range')),
    sa.ForeignKeyConstraint(['batch_id'], ['scan_batches.id'], name=op.f('fk_scan_jobs_batch_id_scan_batches'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan_jobs'))
    )
    op.create_index(op.f('ix_scan_jobs_batch_id'), 'scan_jobs', ['batch_id'], unique=False)
    op.create_index('uq_scan_jobs_active_target', 'scan_jobs', ['target_fingerprint'], unique=True, postgresql_where=sa.text("status IN ('pending', 'validating', 'running')"))
    op.create_table('scan_inventory_items',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('job_id', sa.UUID(), nullable=False),
    sa.Column('location_kind', sa.String(length=16), nullable=False),
    sa.Column('location_locator', sa.Text(), nullable=False, comment='Plain text in v1; not column-level encrypted or pseudonymized'),
    sa.Column('field_locator', sa.Text(), nullable=True),
    sa.Column('pii_type', sa.String(length=64), nullable=False),
    sa.Column('match_count', sa.BigInteger(), nullable=False),
    sa.Column('units_with_pii', sa.BigInteger(), nullable=False),
    sa.Column('units_scanned', sa.BigInteger(), nullable=False),
    sa.Column('bytes_scanned', sa.BigInteger(), nullable=False),
    sa.Column('confidence_band', sa.String(length=16), nullable=False),
    sa.Column('detector_version', sa.String(length=64), nullable=False),
    sa.Column('coverage_status', sa.String(length=16), nullable=False),
    sa.Column('warnings_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("confidence_band IN ('low', 'medium', 'high', 'unassessed')", name=op.f('ck_scan_inventory_items_confidence_valid')),
    sa.CheckConstraint("coverage_status IN ('complete', 'partial', 'failed', 'unassessed')", name=op.f('ck_scan_inventory_items_coverage_status_valid')),
    sa.CheckConstraint('field_locator IS NULL OR length(field_locator) > 0', name=op.f('ck_scan_inventory_items_field_locator_not_empty')),
    sa.CheckConstraint('length(location_locator) > 0', name=op.f('ck_scan_inventory_items_locator_not_empty')),
    sa.CheckConstraint('match_count >= 0 AND units_with_pii >= 0 AND units_scanned >= 0 AND bytes_scanned >= 0', name=op.f('ck_scan_inventory_items_metrics_nonnegative')),
    sa.CheckConstraint('units_with_pii <= units_scanned', name=op.f('ck_scan_inventory_items_pii_units_within_scanned')),
    sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], name=op.f('fk_scan_inventory_items_job_id_scan_jobs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan_inventory_items'))
    )
    op.create_index(op.f('ix_scan_inventory_items_job_id'), 'scan_inventory_items', ['job_id'], unique=False)
    op.create_index('uq_inventory_item_identity', 'scan_inventory_items', ['job_id', 'location_locator', sa.literal_column("COALESCE(field_locator, '')"), 'pii_type', 'detector_version'], unique=True)
    op.create_table('scan_reports',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('job_id', sa.UUID(), nullable=False),
    sa.Column('total_matches', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('units_with_pii', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('high_risk_flags', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
    sa.Column('report_schema_version', sa.String(length=64), nullable=False),
    sa.Column('report_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('total_matches >= 0 AND units_with_pii >= 0 AND high_risk_flags >= 0', name=op.f('ck_scan_reports_totals_nonnegative')),
    sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], name=op.f('fk_scan_reports_job_id_scan_jobs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_scan_reports')),
    sa.UniqueConstraint('job_id', name=op.f('uq_scan_reports_job_id'))
    )
    op.create_table('remediation_items',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('job_id', sa.UUID(), nullable=False),
    sa.Column('inventory_item_id', sa.UUID(), nullable=True),
    sa.Column('rule_id', sa.String(length=64), nullable=False),
    sa.Column('rule_version', sa.String(length=64), nullable=False),
    sa.Column('risk_score', sa.Integer(), nullable=False),
    sa.Column('risk_band', sa.String(length=16), nullable=False),
    sa.Column('reason_codes_json', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('evidence_state', sa.String(length=24), nullable=False),
    sa.Column('control_state', sa.String(length=24), nullable=False),
    sa.Column('recommended_control', sa.Text(), nullable=False),
    sa.Column('suggested_owner', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=24), server_default=sa.text("'open'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("control_state IN ('present', 'absent', 'partial', 'not_applicable', 'unknown')", name=op.f('ck_remediation_items_control_state_valid')),
    sa.CheckConstraint("evidence_state IN ('observed', 'operator_attested', 'unknown')", name=op.f('ck_remediation_items_evidence_state_valid')),
    sa.CheckConstraint("risk_band IN ('red', 'amber', 'green', 'grey')", name=op.f('ck_remediation_items_risk_band_valid')),
    sa.CheckConstraint("status IN ('open', 'accepted', 'resolved', 'risk_accepted')", name=op.f('ck_remediation_items_status_valid')),
    sa.CheckConstraint('risk_score >= 0', name=op.f('ck_remediation_items_risk_score_nonnegative')),
    sa.ForeignKeyConstraint(['inventory_item_id'], ['scan_inventory_items.id'], name=op.f('fk_remediation_items_inventory_item_id_scan_inventory_items'), ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], name=op.f('fk_remediation_items_job_id_scan_jobs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_remediation_items'))
    )
    op.create_index(op.f('ix_remediation_items_inventory_item_id'), 'remediation_items', ['inventory_item_id'], unique=False)
    op.create_index(op.f('ix_remediation_items_job_id'), 'remediation_items', ['job_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_remediation_items_job_id'), table_name='remediation_items')
    op.drop_index(op.f('ix_remediation_items_inventory_item_id'), table_name='remediation_items')
    op.drop_table('remediation_items')
    op.drop_table('scan_reports')
    op.drop_index('uq_inventory_item_identity', table_name='scan_inventory_items')
    op.drop_index(op.f('ix_scan_inventory_items_job_id'), table_name='scan_inventory_items')
    op.drop_table('scan_inventory_items')
    op.drop_index('uq_scan_jobs_active_target', table_name='scan_jobs', postgresql_where=sa.text("status IN ('pending', 'validating', 'running')"))
    op.drop_index(op.f('ix_scan_jobs_batch_id'), table_name='scan_jobs')
    op.drop_table('scan_jobs')
    op.drop_index(op.f('ix_scan_batches_created_by'), table_name='scan_batches')
    op.drop_table('scan_batches')
    op.drop_index(op.f('ix_auth_sessions_user_id'), table_name='auth_sessions')
    op.drop_table('auth_sessions')
    op.drop_index(op.f('ix_audit_events_created_at'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_actor_user_id'), table_name='audit_events')
    op.drop_table('audit_events')
    op.drop_table('users')
