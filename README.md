# DPMAP

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Tests](https://img.shields.io/badge/backend%20tests-25%20passing-brightgreen)
![License](https://img.shields.io/badge/license-not%20selected-lightgrey)
![Python](https://img.shields.io/badge/Python-3.11.15-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.141.1-009688)
![React](https://img.shields.io/badge/React-19.2.8-149eca)
![Coverage](https://img.shields.io/badge/backend%20coverage-100%25-brightgreen)

A read-only DPDPA data-mapping and Section 8-aligned storage gap assessment engine.

## Overview

DPMAP will scan PostgreSQL, MySQL, and service-visible directories for configured Indian PII patterns, discard matched values after aggregation, and combine independent jobs into audit-oriented inventory and remediation reports. It will not determine legal compliance, provision credentials, alter scan targets, erase source data, or persist matched PII values.

## Architecture

```text
React UI -> FastAPI API -> PostgreSQL metadata store
                  |
          in-process coordinator
             /           \
      DB adapters     directory adapter
             \           /
        aggregate-and-discard pipeline
```

## Setup

Prerequisites: [uv](https://docs.astral.sh/uv/) and Node.js 24.19.0 with npm 11.19.0.

Install and run the backend:

```bash
cd DPMAP/backend
uv sync --locked
APP_DB_URL=postgresql+psycopg://dpmap_app@localhost/dpmap \
JWT_SECRET=replace-with-at-least-32-bytes \
ALLOWED_SCAN_ROOTS=/srv/dpmap-scans \
ALLOWED_DB_HOSTS=db.internal \
  uv run --no-sync uvicorn dpmap.main:app --app-dir src --reload --port 8765
```

Apply metadata migrations to an empty PostgreSQL database:

```bash
cd DPMAP/backend
APP_DB_URL=postgresql+psycopg://dpmap_app@db.internal/dpmap \
  uv run --no-sync alembic upgrade head
```

Install and run the frontend in a second terminal:

```bash
cd DPMAP/frontend
npm ci
npm run dev
```

Run the verified checks:

```bash
cd DPMAP/backend
uv run --no-sync flake8 src
uv run --no-sync pytest --cov=dpmap --cov-report=term-missing

cd ../frontend
npm run lint
npm test
npm run build
```

## Usage

The API currently exposes process health and authentication:

```bash
curl http://127.0.0.1:8765/health
# {"status":"ok","version":"0.1.0"}
```

- `POST /api/v1/auth/login` issues a 15-minute JWT backed by a revocable session.
- `POST /api/v1/auth/logout` revokes the current session.
- `POST /api/v1/scans/directory` starts one asynchronous `.txt`/`.csv`/`.xlsx` directory job under `ALLOWED_SCAN_ROOTS`.
- `POST /api/v1/scans/postgres` starts one asynchronous PostgreSQL job against an exact host in `ALLOWED_DB_HOSTS`; credentials remain in process memory only.
- `GET /api/v1/jobs/{job_id}/status` returns progress, coverage, aggregate counts, and sanitized failures.
- `PYTHONPATH=src uv run --no-sync python -m dpmap.cli create-admin --email admin@example.test` creates the first Admin using a hidden password prompt.

The PostgreSQL adapter is verified against PostgreSQL 17. It enforces read-only rollback-only transactions, quoted identifiers, bounded server cursors, statement/idle/total timeouts, and privilege reporting. `verify-full` TLS is the default; weaker modes require `ALLOW_INSECURE_TARGET_TLS=true` and produce a warning. MySQL and report endpoints remain unimplemented. Their accepted contract is documented in [the build plan](Docs/build-plan.md#9-api-contract).

The internal detector pipeline now accepts bounded text chunks and returns only aggregate counts, confidence, and static reason codes. Matched values and source coordinates are discarded before serialization.

Location locators are plain text in v1 and rely on RBAC and PostgreSQL access controls. See the [metadata retention and locator limitation](Docs/data-retention.md).

## Project Status

- [x] Task 1: Freeze terminology, rule set, and acceptance corpus - complete
- [x] Task 2: Bootstrap pinned backend/frontend projects and CI - complete
- [x] Task 3: Metadata schema and migrations - complete
- [x] Task 4: Authentication and RBAC - complete
- [x] Task 5: Aggregate-and-discard boundary - complete
- [x] Task 6: Directory scan vertical slice - complete
- [x] Task 7: PostgreSQL scan vertical slice - complete
- [ ] Task 8: MySQL scan vertical slice - not started
- [ ] Tasks 9-11: Batch orchestration, assessment, and reports - not started
- [ ] Tasks 12-15: Operator and reviewer UI - not started
- [ ] Tasks 16-18: Security proof, performance envelope, and release evidence - not started

See [Docs/build-plan.md](Docs/build-plan.md) for the full implementation sequence and [Docs/agent-log.md](Docs/agent-log.md) for research and decisions.
