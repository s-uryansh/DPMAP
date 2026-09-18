# Build Plan: DPDPA Data Mapping and Section 8 Gap Assessment Engine v2

**Status:** Implementation in progress — Tasks 1-7 complete
**Prepared:** 2026-09-11  
**Implementation gate:** Open Questions 4-6 were resolved with owner-authorized engineering defaults on 11 September 2026. Remaining open questions are handled when their dependent task is reached.

## 1. Outcome

Build a read-only discovery service for IT/DBA/Infra operators that scans one PostgreSQL database, MySQL database, or service-visible directory per job; groups independently executed jobs into a batch; discards matched values after counting; and presents a batch-level inventory, transparent Section 8-aligned storage-risk heatmap, and CSV remediation tracker.

The product supports DPO/GRC review. It does **not** determine legal compliance, provision credentials, alter target data, erase data, inspect network traffic, or retain detected values.

## 2. Corrections to the Supplied Plan

1. As of 11 September 2026, Section 8 and most relevant final DPDP Rules are notified but not yet operative. The [commencement notification](https://www.meity.gov.in/static/uploads/2025/11/c56ceae6c383460ca69577428d36828b.pdf) schedules Sections 7-10 and Rules 5-16 for 18 months after 13 November 2025. Store a rule-set version/effective date and have counsel verify the exact commencement date before release.
2. The DPDP Act does not prescribe a GDPR Article 30 RoPA. The deliverable is a **Data Inventory / RoPA-style extract**. Purpose, recipients, transfers, retention basis, processor, and owner require human governance input.
3. Reading clear text does not prove unencrypted storage: database/disk encryption is transparent to authorised clients. The engine can report visible PII and control evidence, not infer encryption at rest.
4. Absolute "zero PII in the app database" is incompatible with storing actionable paths/table names that may themselves contain names. The enforceable invariant is **zero matched-value persistence**. Location metadata remains protected application data.
5. A write-attempt permission test conflicts with strict read-only behavior and is incomplete. Use non-mutating privilege introspection plus enforced read-only transactions; report when least privilege cannot be verified.

## 3. Scope and Acceptance Vocabulary

### Included

- PostgreSQL and MySQL text-like columns, including textual JSON values.
- `.csv`, `.txt`, and `.xlsx` files under local or Infra-mounted network paths.
- Built-in PAN, Aadhaar, Indian mobile, email, and person-name detectors.
- Preconfigured administrator-deployed custom detectors; selection only in the UI.
- Per-job progress/failure and derived batch status.
- Job and batch inventory, heatmap, JSON summary, and CSV remediation export.
- JWT authentication, revocable sessions, and `Admin`/`Auditor` export authorization.

### Excluded

- Legacy `.xls`, PDFs, archives, images/OCR, macros, binary/blob content, direct SMB credential handling, source mutation, automated erasure, and arbitrary UI-authored regex.
- Distinct-person counts, matched samples, excerpts, hashes of matched values, and inferred data-subject identity/nationality.
- Email/SMS/webhook alerts; "alert" means an in-app terminal-state notification.
- A legal conclusion that a Data Fiduciary complies with or breaches Section 8.

### Metrics

- `match_count`: detector occurrences.
- `units_with_pii`: DB rows, CSV rows, XLSX cells, or TXT chunks containing a match.
- `units_scanned`: comparable units processed for that location.
- `bytes_scanned`: bytes read where meaningful.
- `coverage`: completed, completed-with-skips/warnings, failed-access, or failed-scan.

## 4. Legal and Evidence Model

The [DPDP Act, Section 8](https://www.indiacode.nic.in/bitstream/123456789/22037/2/a2023-22.pdf) covers accuracy in specified situations, processor accountability, technical and organisational measures, reasonable security safeguards, breach notification, erasure subject to legal retention, and contact/accountability duties. [Rules 6-8](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf) add minimum safeguard and contextual retention detail.

For every assessment item, persist:

- `observation`: what the scanner directly measured.
- `evidence_state`: `observed`, `operator_attested`, or `unknown`.
- `control_state`: `present`, `absent`, `partial`, `not_applicable`, or `unknown`.
- `control_reference`: Section/rule/control identifier and rule-set version.
- `applicability`: `applicable`, `not_applicable`, or `needs_legal_review`.
- `reason_codes`: deterministic inputs to the risk band.

Never translate `unknown` into `absent`. Heatmap meanings are:

| Band | Meaning |
|---|---|
| Red | Confirmed high-impact identifier plus confirmed missing/insufficient relevant control |
| Amber | PII found with unknown/partial controls, or a lower-impact confirmed gap |
| Green | Scan completed and no engine-detected storage gap under supplied evidence; not a compliance certificate |
| Grey | Unassessed, access failed, scan failed, or coverage materially incomplete |

The initial scoring table is code/config reviewed by DPO/legal, versioned, and returned with every result. Avoid a learned or opaque risk model.

## 5. Architecture

```text
React UI
   | HTTPS/JWT, polling
FastAPI API ---- PostgreSQL application DB (metadata and aggregate counts only)
   |
Bounded in-process scan coordinator ---- in-memory credential registry
   |                                  (cleared on terminal state/restart)
   +---- Database adapter ---- read-only transaction + streaming cursor
   +---- Directory adapter --- bounded streaming parser
                     |
              detector pipeline
                     |
          aggregate-and-discard boundary
                     |
          inventory/remediation metadata
```

### Execution decision

FastAPI says heavy work should not rely on request-process [`BackgroundTasks`](https://fastapi.tiangolo.com/tutorial/background-tasks/). For v2, use a bounded coordinator owned by a single deployed API instance. It accepts validated targets and credentials in memory, launches independent jobs, and writes only progress/aggregates to PostgreSQL.

On startup, any orphaned `pending`, `validating`, or `running` job becomes `failed/access_context_lost`. Horizontal scale and restart-resume are deferred until an approved secret manager can issue short-lived references to separate workers. Do not persist credentials or place them in queue payloads.

### Dependency graph

```text
legal/control vocabulary + detector corpus
        |                 |
        +---- schema/types
                  |
         aggregate-only detector pipeline
            |                  |
   directory adapter      DB adapters
            \                  /
             job coordinator/status
                       |
             assessment/report APIs
                       |
              frontend and exports
                       |
             hardening/performance
```

## 6. Scan Pipeline

1. Authenticate and authorize the operator.
2. Validate request shape, target allowlist, detector selection, and resource limits.
3. Canonicalize a non-secret target identity and HMAC it. A PostgreSQL partial unique index prevents two active jobs for one fingerprint.
4. Create the batch and all job records in one application-DB transaction.
5. Preflight each target independently with bounded concurrency. A failed target becomes `failed` without blocking siblings.
6. Register credentials only in coordinator memory and open one target connection/reader for that job.
7. Stream bounded rows/cells/text chunks into deterministic detectors, then name NER.
8. Immediately reduce candidates to aggregate counters and discard source text/matches before persistence or logging.
9. Periodically persist monotonic progress and inventory aggregates in small transactions.
10. Evaluate versioned risk rules from observations plus supplied control evidence.
11. Close/rollback target resources, clear secrets, finalize job/report, and let batch status derive from children.

### Database adapter rules

- Use `NullPool`/one-shot connections so target credentials and idle sessions are not retained. SQLAlchemy documents [`NullPool`](https://docs.sqlalchemy.org/en/20/core/pooling.html) as opening/closing per connection.
- Require TLS verification by default; weakening it requires an explicit warning and configuration flag.
- Set PostgreSQL or MySQL transaction mode to read-only before scanning. PostgreSQL documents the restrictions and limits of [`READ ONLY`](https://www.postgresql.org/docs/current/sql-set-transaction.html); MySQL notes temporary-table exceptions in [`START TRANSACTION READ ONLY`](https://dev.mysql.com/doc/refman/8.4/en/innodb-performance-ro-txn.html).
- Use server-side/unbuffered cursors and fixed batches. Psycopg and SQLAlchemy document [server cursors](https://www.psycopg.org/psycopg3/docs/advanced/cursors.html) and [`yield_per`](https://docs.sqlalchemy.org/en/20/core/engines_connections.html).
- Generate only metadata queries and `SELECT` statements. Quote discovered identifiers through the driver/expression API. Do not concatenate identifiers or accept free-form SQL.
- Scan textual, character, enum, and JSON textual content; skip binary/spatial/unsupported types with coverage reasons.
- Apply connect, statement, idle-transaction, and total-job timeouts; check cancellation between batches.
- Preflight privileges without writes and report `verified_limited`, `overprivileged`, or `unverifiable`.

### Directory adapter rules

- The path is visible to the service host. Infra mounts SMB/CIFS shares; the app does not manage SMB credentials.
- Restrict roots, resolve canonical paths, reject traversal outside allowed roots, and never follow symlinks/reparse points. Python warns that following links in [`os.walk`](https://docs.python.org/3.11/library/os.html) can recurse indefinitely.
- Traverse deterministically; continue through recoverable file errors and record each skip/error.
- TXT: incremental decoding with configured fallback and overlapping bounded chunks.
- CSV: stdlib streaming reader with `newline=''`, dialect/encoding detection bounded to a prefix, and a maximum field size. See the Python [`csv` documentation](https://docs.python.org/3.11/library/csv.html).
- XLSX: openpyxl `read_only=True`, `data_only=True`, explicit close, and preflight ZIP entry/decompressed-size limits. See [openpyxl optimized mode](https://openpyxl.readthedocs.io/en/stable/optimized.html).
- Detect file mutation by comparing metadata before/after reading; record `unstable_file` rather than asserting complete coverage.

## 7. Detector Contract

Each detector returns ephemeral `{type, start, end, confidence, reason_codes}` candidates. The aggregation boundary receives candidates and source coordinates, increments counters, and returns no source text.

| Type | Candidate rule | Validation/context | Default handling |
|---|---|---|---|
| PAN | Five letters, four digits, one letter, strict boundaries | Uppercase normalization; header/context boost; code-like negatives | High confidence only with valid shape and context |
| Aadhaar | 12 digits with permitted spaces/hyphens | Verhoeff checksum; full vs masked classification | Full valid Aadhaar high impact; masked reported separately |
| Indian mobile | Normalize `+91`/`91`/leading zero and punctuation | Ten-digit mobile-series rule; boundary/context checks | Configurable series table; reject embedded numeric IDs |
| Email | Pragmatic local/domain candidate with length/boundary constraints | Domain/label context; malformed/log-token negatives | No full RFC mailbox validation claim |
| Person name | spaCy `PERSON` candidate | Column/header/context signals and calibrated threshold | Lower confidence; disabled if corpus gate fails |

UIDAI describes Aadhaar as a [12-digit random number](https://www.uidai.gov.in/en/286-english-uk/faqs/your-aadhaar/aadhaar-features%2C-eligibility/1933-what-is-aadhaar.html) and requires 12 digits plus [Verhoeff validation](https://uidai.gov.in/en/ecosystem/authentication-devices-documents/developer-section/data-and-downloads-section.html). Income Tax documentation gives the [PAN character structure](https://www.incometax.gov.in/iec/foportal/node/11593).

Use spaCy `nlp.pipe` with bounded batches and only needed components, following its [pipeline efficiency guidance](https://spacy.io/usage/processing-pipelines). `en_core_web_sm` is not a PII model; spaCy documents [whole-span and boundary limitations](https://spacy.io/api/entityrecognizer). Release name detection only after per-domain precision/recall review.

## 8. Application Schema

Use UUID primary keys, UTC timestamps, foreign keys, check constraints, and Alembic migrations.

### `users`

`id`, `email` (unique normalized), `role` (`admin|auditor`), `password_hash`, `is_active`, `created_at`, `updated_at`.

### `auth_sessions`

`id`/JWT `jti`, `user_id`, `expires_at`, `revoked_at`, `created_at`. Store no raw token. Logout revokes the session; authorization checks `jti` and role.

### `scan_batches`

`id`, `label`, `created_by`, `created_at`. Batch status is computed from jobs, not stored.

### `scan_jobs`

`id`, `batch_id`, `target_name`, `target_type` (`database|directory`), `target_engine` (`postgresql|mysql|null`), `target_display`, `target_fingerprint`, `status`, `stage`, `progress_percent`, metric counters, `detector_config_json`, `governance_context_json`, `control_evidence_json`, `permission_check_status`, `coverage_status`, `error_code`, sanitized `error_message`, `created_at`, `started_at`, `finished_at`, `heartbeat_at`.

Constraints: progress 0-100; terminal states require `finished_at`; error code only on failed/warning states. Add a partial unique index on `target_fingerprint` for active states.

### `scan_inventory_items`

`id`, `job_id`, `location_kind`, normalized `location_locator`, optional `field_locator`, `pii_type`, `match_count`, `units_with_pii`, `units_scanned`, `bytes_scanned`, `confidence_band`, `detector_version`, `coverage_status`, `warnings_json`, `created_at`.

Unique key: job + location + field + PII type + detector version. No samples/excerpts/value hashes.

### `remediation_items`

`id`, `job_id`, optional `inventory_item_id`, `rule_id`, `rule_version`, `risk_score`, `risk_band`, `reason_codes_json`, `evidence_state`, `control_state`, `recommended_control`, `suggested_owner`, `status` (`open|accepted|resolved|risk_accepted`), `created_at`, `updated_at`.

### `scan_reports`

`id`, `job_id` (unique), aggregate totals, `report_schema_version`, small `report_json`, `created_at`. Batch reports are computed queries across child reports/items.

### `audit_events`

`id`, `actor_user_id`, `action`, `object_type`, `object_id`, sanitized `details_json`, `created_at`. Record login/logout, batch creation, job outcome, report view, and export; never record credentials or matched content.

Application metadata retention must be configured and documented because locators, user accounts, and audit events can themselves be personal data.

## 9. API Contract

All bodies are JSON unless exporting. Errors use `{code, message, field_errors?, request_id}` and never echo secrets or raw driver errors.

### Authentication

- `POST /api/v1/auth/login` -> `200 {access_token, token_type, expires_at, user}`; generic `401` on failure.
- `POST /api/v1/auth/logout` -> `204`; revoke current `jti`.

Bootstrap of the first Admin is deployment configuration/CLI, not a public registration endpoint.

### Create a batch

`POST /api/v1/batches` -> `202`

```json
{
  "label": "Q3 plant and HR audit",
  "targets": [
    {
      "client_ref": "hr-db",
      "target_name": "HR PostgreSQL",
      "type": "database",
      "database": {
        "engine": "postgresql",
        "host": "db.internal",
        "port": 5432,
        "database": "hr",
        "username": "dpmap_reader",
        "password": "request-only secret",
        "tls_mode": "verify-full"
      },
      "scope": {"schemas": ["public"]},
      "detectors": ["pan", "aadhaar", "phone", "email", "person_name"],
      "governance_context": {"purpose": null, "owner": "HR IT"},
      "control_evidence": {
        "encryption_at_rest": "unknown",
        "retention_policy": "unknown",
        "access_control": "operator_attested_present"
      }
    },
    {
      "client_ref": "plant-share",
      "target_name": "Plant vendor extracts",
      "type": "directory",
      "directory": {"path": "/mnt/plant/vendor-room"},
      "detectors": ["pan", "aadhaar", "phone", "email"]
    }
  ]
}
```

Response: `{batch_id, jobs:[{job_id, client_ref, status, status_url}], batch_status_url}`. Create a failed job for a target that fails preflight; do not reject valid siblings. Reject the entire request only for authentication, malformed batch shape, batch-size limit, or application-DB failure.

Optional one-target convenience endpoints `/api/v1/scans/postgres`, `/mysql`, and `/directory` call the same batch service; do not build separate orchestration paths.

### Status and reports

- `GET /api/v1/jobs/{job_id}/status` -> stage, percent, counters, coverage, sanitized error.
- `GET /api/v1/batches/{batch_id}/status` -> derived status and all child summaries.
- `GET /api/v1/jobs/{job_id}/inventory?pii_type=&risk_band=&page=&page_size=` -> paginated items.
- `GET /api/v1/jobs/{job_id}/heatmap` -> band cells plus evidence/reason codes.
- `GET /api/v1/jobs/{job_id}/remediations?...` -> paginated remediation items.
- `GET /api/v1/jobs/{job_id}/report` -> versioned machine-readable summary.
- `GET /api/v1/batches/{batch_id}/report?...` -> aggregate summary and paginated inventory/remediation links.
- `GET /api/v1/jobs/{job_id}/export?format=csv` and `/batches/{batch_id}/export?format=csv` -> streamed remediation CSV; `Admin|Auditor` only.

Status semantics:

- Job: `pending`, `validating`, `running`, `completed`, `completed_with_warnings`, `failed`, `cancelled`.
- Batch: `pending`, `running`, `completed`, `completed_with_failures`, `failed`, `cancelled` (derived).
- `completed` with zero findings is a clean negative for scanned coverage; access failure is `failed`; skipped files/columns yield `completed_with_warnings`.

## 10. Proposed Repository Structure

```text
DPMAP/
  Docs/
    build-plan.md
    agent-log.md
  backend/
    pyproject.toml
    alembic.ini
    migrations/
    src/dpmap/
      main.py
      api/{dependencies,schemas,routes}/
      core/{config,logging,security}.py
      db/{session,models}.py
      engine/
        detectors/{base,patterns,aadhaar,ner,pipeline}.py
        scanners/{base,database,postgres,mysql,directory,files}.py
        assessment/{rules,service}.py
        reporting/{service,export}.py
      jobs/{coordinator,service}.py
    tests/{unit,integration,security,performance}/
  frontend/
    package.json
    src/
      api/
      components/
      pages/
      features/{auth,scans,inventory,remediation,settings}/
    tests/
  .github/workflows/ci.yml
```

Exact dependency versions are chosen and pinned during bootstrap after compatibility checks; none exist in the empty repository today.

## 11. Implementation Tasks

### Phase 0 - Decisions and Quality Baseline

#### Task 1: Freeze terminology, rule set, and acceptance corpus

**Description:** Convert the legal/evidence vocabulary and synthetic examples into versioned fixtures before building detectors.

**Acceptance criteria:** DPO-approved heatmap meanings; corpus covers positives/near-misses for every detector; no fixture contains real personal data.

**Verification:** Review checklist signed; corpus schema validates; legal source URLs/effective status are captured.

**Dependencies:** None.  
**Files likely touched:** `Docs/`, `backend/tests/fixtures/`, `backend/src/dpmap/engine/assessment/`.  
**Scope:** Medium.

#### Task 2: Bootstrap pinned backend/frontend projects and CI

**Description:** Create minimal FastAPI/Python 3.11 and React/Vite/TypeScript/Tailwind projects with lint, test, and build commands.

**Acceptance criteria:** Dependencies pinned; spaCy model installation is reproducible; CI runs backend lint/tests and frontend lint/tests/build.

**Verification:** `flake8 backend/src`; `pytest backend/tests`; `npm run lint`; `npm test`; `npm run build`.

**Dependencies:** Task 1.  
**Files likely touched:** `backend/pyproject.toml`, `frontend/package.json`, frontend config files, `.github/workflows/ci.yml`.  
**Scope:** Medium.

### Checkpoint A

- Human accepts open decisions and risk vocabulary.
- Empty skeleton builds; no scanner behavior exists yet.

### Phase 1 - Metadata, Auth, and Aggregate Boundary

#### Task 3: Create metadata schema and migrations

**Description:** Implement the tables/constraints/indexes in the schema section above, including the active-target uniqueness rule.

**Acceptance criteria:** Upgrade/downgrade works on a clean PostgreSQL database; invalid status/progress combinations fail; credentials/matched values have no columns.

**Verification:** Migration integration test plus schema inspection assertion.

**Dependencies:** Task 2.  
**Files likely touched:** `db/models.py`, migration files, `tests/integration/test_schema.py`.  
**Scope:** Medium.

#### Task 4: Implement authentication and RBAC

**Status:** Complete — verified against PostgreSQL 17 on 11 September 2026.

**Description:** Add password hashing, short-lived JWT/JTI sessions, login/logout, route dependencies, and initial-Admin bootstrap.

**Acceptance criteria:** Revoked/expired tokens fail; inactive users fail; only Admin/Auditor can export.

**Verification:** Focused API tests for login, logout, expiry, and role matrix.

**Dependencies:** Task 3.  
**Files likely touched:** `core/security.py`, auth routes/schemas, `db/models.py`, `tests/integration/test_auth.py`.  
**Scope:** Medium.

#### Task 5: Build aggregate-and-discard detector pipeline

**Status:** Complete — verified against the frozen seed corpus on 11 September 2026; production corpus-size and DPO/legal review gates remain pending.

**Description:** Implement compiled deterministic detectors, Aadhaar checksum, candidate merge, confidence/reason codes, and aggregate-only output; add spaCy name candidates behind a threshold.

**Acceptance criteria:** Corpus precision/recall meets Task 1 gates; chunk-boundary matches are counted once; pipeline result contains no source substrings.

**Verification:** `pytest backend/tests/unit/test_detectors.py` with positive/negative and serialization-leak assertions.

**Dependencies:** Tasks 1-2.  
**Files likely touched:** detector modules, `tests/unit/test_detectors.py`, fixtures.  
**Scope:** Medium.

### Checkpoint B

- Schema/auth tests pass.
- A memory-only string stream produces only aggregate counters.

### Phase 2 - Single-Target Vertical Slices

#### Task 6: Deliver directory scan from API to inventory

**Status:** Complete — verified with a real PostgreSQL 17 metadata store on 11 September 2026.

**Description:** Add safe traversal, TXT/CSV/XLSX streaming, coordinator execution, progress, and aggregate inventory persistence for one directory job.

**Acceptance criteria:** Supported files scan with bounded memory; permission/skipped/unstable files affect coverage; symlinks and disallowed roots are rejected/skipped.

**Verification:** Temporary-tree integration test and a large synthetic-file RSS ceiling check.

**Dependencies:** Tasks 3-5.  
**Files likely touched:** directory/files scanners, coordinator/service, batch route, `tests/integration/test_directory_job.py`.  
**Scope:** Medium.

#### Task 7: Deliver PostgreSQL scan from API to inventory

**Status:** Complete — verified with PostgreSQL 17 and a server-side SQL statement trace on 15 September 2026.

**Description:** Add preflight, metadata discovery, enforced read-only transaction, quoted SELECTs, streaming batches, timeouts, and privilege status.

**Acceptance criteria:** Exact aggregate counts match fixture DB; SQL trace contains only approved read/transaction statements; timeout/failure closes and rolls back.

**Verification:** Containerized PostgreSQL integration tests with read-only and overprivileged users.

**Dependencies:** Tasks 3-5.  
**Files likely touched:** database/postgres scanners, coordinator/service, schemas, `tests/integration/test_postgres_job.py`.  
**Scope:** Medium.

#### Task 8: Deliver MySQL scan through the same contract

**Status:** Complete — verified with MySQL 8.4.11 on Linux/Docker and server-side Performance Schema SQL traces on 15 September 2026.

**Description:** Implement MySQL-specific metadata, read-only transaction, privilege introspection, and unbuffered streaming behind the shared database adapter contract.

**Acceptance criteria:** Same behavioral contract as PostgreSQL; MySQL failures use shared error codes; unsupported types are coverage warnings.

**Verification:** Containerized MySQL integration tests using the adapter contract suite.

**Dependencies:** Task 7.  
**Files likely touched:** MySQL scanner, database base, schemas, `tests/integration/test_mysql_job.py`.  
**Scope:** Medium.

### Checkpoint C

- Each target type completes independently and never persists a sample.
- Failure/access/no-findings states are distinguishable via API.

### Phase 3 - Batch, Assessment, and Reports

#### Task 9: Implement batch orchestration and mixed outcomes

**Status:** Complete — verified with a real PostgreSQL 17 metadata/scan target and mixed directory/PostgreSQL/failing-target execution on 15 September 2026.

**Description:** Create all target jobs together, preflight/run siblings independently, derive batch status, and enforce same-target exclusion.

**Acceptance criteria:** One failed target does not stop siblings; mixed result is `completed_with_failures`; duplicate active fingerprint returns a stable conflict code.

**Verification:** Mixed Postgres/directory/failing-target integration test and restart orphan test.

**Dependencies:** Tasks 6-8.  
**Files likely touched:** jobs coordinator/service, batch routes/schemas, `tests/integration/test_batches.py`.  
**Scope:** Medium.

#### Task 10: Implement transparent assessment rules

**Description:** Map inventory plus control evidence to versioned score, band, reasons, remediation, and owner suggestions.

**Acceptance criteria:** Unknown controls never become confirmed gaps; grey coverage is preserved; every score is reproducible from returned reasons/rule version.

**Verification:** Table-driven unit test for every risk/evidence combination.

**Dependencies:** Tasks 1, 5, 9.  
**Files likely touched:** assessment rules/service, models, `tests/unit/test_assessment.py`.  
**Scope:** Small.

#### Task 11: Implement job/batch queries and exports

**Description:** Add paginated inventory/remediation, heatmap, versioned JSON summaries, and streaming RFC-4180-compatible CSV tracker exports.

**Acceptance criteria:** Batch totals equal child totals; filters paginate stably; spreadsheet-formula-leading CSV values are neutralized; RBAC is enforced.

**Verification:** API contract tests and CSV round-trip/security tests.

**Dependencies:** Tasks 4, 9-10.  
**Files likely touched:** reporting service/export, report routes/schemas, `tests/integration/test_reports.py`.  
**Scope:** Medium.

### Checkpoint D

- Required engine/API Definition of Done passes end to end.
- DPO reviews one generated inventory, heatmap rationale, and remediation CSV.

### Phase 4 - Operator and Reviewer UI

#### Task 12: Build authenticated shell and multi-target batch form

**Description:** Add login, restrained enterprise navigation, database/directory target rows, detector selection, control-evidence inputs, and connection-error display.

**Acceptance criteria:** Secrets stay only in form/request memory; form clearly says paths are service-visible; malformed targets are blocked accessibly.

**Verification:** Component tests and browser flow with mocked API.

**Dependencies:** Tasks 4, 9.  
**Files likely touched:** auth/scans features, API client, pages, UI tests.  
**Scope:** Medium.

#### Task 13: Build batch progress and outcome view

**Description:** Poll batch status with backoff and show stable per-target progress, clean-zero, warning, and failed-access states.

**Acceptance criteria:** Slow/failed siblings do not hide completed results; polling stops at terminal state; mixed outcome gets an in-app alert.

**Verification:** Fake-timer tests and mixed-status browser test.

**Dependencies:** Task 12.  
**Files likely touched:** scans feature/components, API client, UI tests.  
**Scope:** Small.

#### Task 14: Build inventory, heatmap, and remediation views

**Description:** Add server-paginated/filterable inventory, accessible Recharts risk visualization, evidence drawer, remediation table, JSON view, and exports.

**Acceptance criteria:** Red/amber/green/grey never rely on color alone; job/target filters work; export and machine-readable views honor RBAC.

**Verification:** Component tests, keyboard/accessibility audit, desktop/mobile Playwright screenshots.

**Dependencies:** Tasks 11-13.  
**Files likely touched:** inventory/remediation features, shared chart/table components, UI tests.  
**Scope:** Medium.

#### Task 15: Build bounded Settings view

**Description:** Expose detector enablement, confidence thresholds, chunk/file/time limits, and rule/model version; no arbitrary regex editor.

**Acceptance criteria:** Numeric bounds validate; changes create a versioned configuration snapshot; existing reports retain their original versions.

**Verification:** Settings validation/versioning tests.

**Dependencies:** Tasks 5, 12.  
**Files likely touched:** settings feature, settings API/schema/service, tests.  
**Scope:** Medium.

### Phase 5 - Security, Scale, and Release Evidence

#### Task 16: Prove the zero-matched-value and read-only invariants

**Description:** Add log/DB/export leak canaries, SQL statement tracing, secret redaction, locator access tests, and audit events.

**Acceptance criteria:** Synthetic canary values are absent from DB/logs/errors/JSON/CSV; target statement trace has no mutation; secrets are cleared on every terminal path.

**Verification:** `pytest backend/tests/security` against success, failure, timeout, and cancellation paths.

**Dependencies:** Tasks 6-15.  
**Files likely touched:** security tests, logging/security helpers, audit service.  
**Scope:** Medium.

#### Task 17: Establish performance and failure envelopes

**Description:** Measure bounded memory, target load, timeout recovery, deeply nested paths, malformed XLSX/CSV, and UI behavior with large metadata sets.

**Acceptance criteria:** Agreed resource budgets pass; scan concurrency is bounded; partial coverage and restart failures are accurate; no UI freezes on paginated datasets.

**Verification:** Performance scripts/results plus manual QA checklist; run scheduled/ release-gate tests rather than slowing every PR unnecessarily.

**Dependencies:** Task 16.  
**Files likely touched:** performance tests/scripts, fixture generators, `Docs/` results.  
**Scope:** Medium.

#### Task 18: Finalize runbooks and release gate

**Description:** Document setup, read-only grants, mounted-share prerequisites, credential handling, legal coverage limits, backup/retention for metadata, incident handling, and upgrade path to external workers.

**Acceptance criteria:** A fresh environment follows documented setup; DBA validates grants; DPO signs report disclaimers/rules; all CI and Definition of Done checks pass.

**Verification:** Clean-machine rehearsal and signed release checklist.

**Dependencies:** Task 17.  
**Files likely touched:** `README.md`, `Docs/`, deployment config examples.  
**Scope:** Medium.

### Final Checkpoint

- All unit, integration, security, UI, build, and required performance checks pass.
- PostgreSQL, MySQL, and directory jobs work alone and in mixed batches.
- Failed access, partial coverage, clean zero, and confirmed findings are visually/API-distinct.
- No target mutation and no matched-value persistence are proven by automated canaries.
- Human DPO/legal review accepts rule applicability, effective dates, and wording.

## 12. Test Strategy

| Layer | Minimum evidence |
|---|---|
| Detector unit | Synthetic positive, invalid, boundary, context, checksum, chunk-overlap, Unicode/encoding, and collision cases; precision/recall by type |
| Assessment unit | Exhaustive table of evidence/control/coverage states and stable rule-version output |
| File integration | Nested tree, denied path, symlink loop, mixed encodings/dialects, large fields, malformed/oversized XLSX, changing file |
| DB integration | Real PostgreSQL/MySQL services, read-only and admin credentials, TLS/timeout errors, quoted identifiers, JSON/text types, exact counts |
| Batch integration | Mixed success/failure, same-target race, app restart, sibling independence, monotonic progress |
| Security | JWT/RBAC, SSRF/root allowlists, CSV injection, secret/error redaction, SQL trace, matched-value canary leakage |
| API contract | Status semantics, pagination/filter stability, JSON schema version, aggregate equality, export headers/content |
| UI | Form validation, mixed progress, failure vs zero, filters, accessible heatmap/table, responsive layout |
| Performance | Bounded RSS on large streams, DB batch/load budget, deep share latency, large inventory pagination |

CI uses synthetic data only. Never copy production PII into fixtures or test artifacts.

## 13. Operational and Security Controls

- Run scanners under a dedicated OS identity with read access only to configured roots.
- Deny the application metadata database and deployment directories as scan targets.
- Restrict target hosts by deployment allowlist; resolve DNS and re-check resulting addresses to reduce SSRF/rebinding risk.
- Redact passwords, DSNs, query parameters, source values, and raw driver messages at log/error boundaries.
- Keep target concurrency low and configurable; one active job per canonical target.
- Expose progress/heartbeat, scanned/skipped counters, sanitized reason codes, and request/job correlation IDs.
- Clear in-memory secrets immediately after preflight failure or job termination.
- Back up the application DB because it is audit evidence, but apply an approved metadata retention schedule.
- Treat model/detector/risk/config changes as versioned; old reports remain reproducible.

## 14. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| False positives overwhelm reviewers | High | Checksums, context/invalidation, confidence bands, negative corpus, per-type calibration |
| False negatives create false assurance | High | Coverage statement, grey incomplete state, detector recall metrics, no compliance claims |
| Transparent encryption misclassified as plaintext | High | Operator/evidence control state; never infer at-rest encryption from readable content |
| Retention breach inferred without purpose/law | High | Require governance context; `needs_legal_review`; no universal retention duration |
| Scan overloads production DB/share | High | Streaming, one connection/job, bounded concurrency, timeouts, scope filters, DBA runbook |
| PII leaks through logs/errors/report samples | High | Aggregate boundary, canary tests, centralized redaction, no sample feature |
| Path/table metadata itself contains PII | Medium | Minimize/redact display locator, RBAC/audit, application-data retention policy |
| Coordinator restart loses credentials | Medium | Explicit `access_context_lost` and retry; secret-manager worker upgrade for HA |
| UNC path does not resolve on Linux | Medium | Require Infra-mounted share; preflight `unsupported_path`/`not_found` |
| XLSX decompression/resource attack | Medium | Entry/decompressed-size/cell/time limits and read-only parsing |
| Overprivileged credential used | Medium | Non-mutating introspection, read-only transaction, SELECT-only code surface, warning/audit |
| Legal rules/effective dates change | High | Versioned source registry and mandatory legal review before rule-set release |

## 15. Open Questions

These choices materially change implementation or acceptance and need owner approval:

3. Provide allowed database network ranges/DNS suffixes and filesystem roots for each deployment.
5. Clarify whether preconfigured custom identifiers are required at first release and who can deploy/version them.
6. Confirm whether JSON/XML inside DB text columns and CSV cells must be parsed structurally or scanned as bounded text in v2; the proposed baseline scans them as text.

### Resolved Decision Gates

- Directory scan scope and execution: on 11 September 2026 the project owner confirmed `.xlsx` as the v2 Excel format, leaving legacy `.xls` excluded, and approved the bounded single-instance, non-resumable in-process coordinator. Network shares remain Infra-mounted service-visible paths; horizontal workers still require approved short-lived secret references.
- Original Open Questions 4-6: on 11 September 2026 the project owner authorized conservative engineering defaults for detector gates, English/Latin-script name scope, and risk/evidence rules. They are versioned in backend/src/dpmap/engine/assessment/rules.v1.json and explicitly remain pending qualified DPO/legal review; they are not production-ready compliance guidance.
- Metadata retention and locator storage: on 11 September 2026 the project owner authorized a 90-day post-completion retention period for jobs, inventory, remediations, and their reports; a one-year period for audit events; and plain-text location locators protected by application RBAC and database access controls only. This is an engineering-adopted default pending real DPO/legal review, not production-ready compliance guidance. Plain-text locators without column-level encryption are a documented v1 limitation.
- MySQL baseline: on 15 September 2026 the project owner authorized MySQL 8.4 LTS on Linux/Docker for Task 8 development and verification. This is an engineering-adopted default pending real DPO/legal or Infra review of actual deployment targets; it does not establish support for other MySQL versions or operating systems.

## 16. Sources Consulted

- [Digital Personal Data Protection Act, 2023](https://www.indiacode.nic.in/bitstream/123456789/22037/2/a2023-22.pdf)
- [Digital Personal Data Protection Rules, 2025](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf)
- [DPDP Act commencement notification, 13 November 2025](https://www.meity.gov.in/static/uploads/2025/11/c56ceae6c383460ca69577428d36828b.pdf)
- [UIDAI Aadhaar definition](https://www.uidai.gov.in/en/286-english-uk/faqs/your-aadhaar/aadhaar-features%2C-eligibility/1933-what-is-aadhaar.html)
- [UIDAI developer validation guidance](https://uidai.gov.in/en/ecosystem/authentication-devices-documents/developer-section/data-and-downloads-section.html)
- [UIDAI Authentication and Offline Verification Regulations, updated 2025](https://uidai.gov.in/images/The_Aadhaar_Authentication_and_Offline_Verifications_Regulations_2021-_Clean_copy-30122025.pdf)
- [Income Tax PAN field format](https://www.incometax.gov.in/iec/foportal/node/11593)
- [Department of Telecommunications numbering amendment](https://www.dot.gov.in/static/uploads/2025/07/64638bb7d6643bd27a863b1909280c21.pdf)
- [ICO RoPA/accountability checklist](https://ico.org.uk/for-organisations/advice-and-services/audits/data-protection-audit-framework/toolkits/accountability/records-of-processing-and-lawful-basis/)
- [EDPB RoPA example](https://www.edpb.europa.eu/system/files/2023-10/cc_farmaindustria_vfinal_230222_en-rev.pdf)
- [spaCy processing pipelines](https://spacy.io/usage/processing-pipelines)
- [spaCy EntityRecognizer limitations](https://spacy.io/api/entityrecognizer)
- [spaCy rule-based matching](https://spacy.io/usage/rule-based-matching/)
- [Microsoft Presidio analyzer design](https://microsoft.github.io/presidio/analyzer/)
- [PostgreSQL read-only transactions](https://www.postgresql.org/docs/current/sql-set-transaction.html)
- [Psycopg server-side cursors](https://www.psycopg.org/psycopg3/docs/advanced/cursors.html)
- [MySQL 8.4 read-only transactions](https://dev.mysql.com/doc/refman/8.4/en/set-transaction.html)
- [MySQL Connector/Python unbuffered result behavior](https://dev.mysql.com/doc/connector-python/en/connector-python-connectargs.html)
- [MySQL 8.4 Performance Schema statement events](https://dev.mysql.com/doc/refman/8.4/en/performance-schema-statement-tables.html)
- [SQLAlchemy pooling](https://docs.sqlalchemy.org/en/20/core/pooling.html)
- [SQLAlchemy streaming results](https://docs.sqlalchemy.org/en/20/core/engines_connections.html)
- [Python 3.11 filesystem traversal](https://docs.python.org/3.11/library/os.html)
- [Python 3.11 CSV](https://docs.python.org/3.11/library/csv.html)
- [openpyxl read-only mode](https://openpyxl.readthedocs.io/en/stable/optimized.html)
- [FastAPI background-task caveat](https://fastapi.tiangolo.com/tutorial/background-tasks/)
