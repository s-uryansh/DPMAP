# Application Metadata Retention

> These are engineering-adopted defaults pending real DPO/legal review. They
> are not production-ready compliance guidance or legal advice.

## Retention Schedule

| Metadata | Retention trigger | Period | Disposition |
|---|---|---:|---|
| `scan_jobs` | `finished_at` | 90 days | Hard-delete |
| `scan_inventory_items` | Parent job `finished_at` | 90 days | Hard-delete with parent job |
| `remediation_items` | Parent job `finished_at` | 90 days | Hard-delete with parent job |
| `scan_reports` | Parent job `finished_at` | 90 days | Hard-delete with parent job |
| `audit_events` | `created_at` | 1 year | Hard-delete |

The schema uses `ON DELETE CASCADE` from a scan job to its inventory,
remediation, and report rows. A retention executor is outside Task 3 and is not
implemented yet. Until it is implemented and scheduled, deployments must not
claim that expiry deletion is automatic.

No retention period has been adopted for users, authentication sessions, or
scan batches. Those records must not be included in the scan-metadata sweep
without a separately reviewed decision.

## Locator Limitation

`scan_jobs.target_display`, `scan_inventory_items.location_locator`, and
`scan_inventory_items.field_locator` are stored as plain text in v1. They are
not column-level encrypted or pseudonymized. Protection depends on application
RBAC, PostgreSQL access controls, deployment security, and backups configured
by the operator.

Locators may themselves contain personal data, such as a filename containing a
person's name. This v1 design therefore has residual confidentiality risk and
must be reviewed before production use. Matched values, source excerpts, source
rows or cells, value hashes, and target credentials remain prohibited from the
application database at all times.
