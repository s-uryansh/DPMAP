"""Bounded PostgreSQL scanning with enforced read-only transactions."""

from dataclasses import dataclass, field
import json
import socket
import time
from typing import Callable

import psycopg
from psycopg import sql

from dpmap.engine.detectors import aggregate_chunks


CONNECT_TIMEOUT_SECONDS = 5
STATEMENT_TIMEOUT_MS = 5_000
IDLE_TRANSACTION_TIMEOUT_MS = 5_000
TOTAL_JOB_TIMEOUT_SECONDS = 60
ROW_BATCH_SIZE = 256


class PostgresScanError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PostgresTarget:
    host: str
    hostaddr: str
    port: int
    database: str
    username: str
    password: str = field(repr=False)
    tls_mode: str = "verify-full"
    schemas: tuple[str, ...] = ("public",)


@dataclass(frozen=True)
class DatabaseInventoryAggregate:
    field_locator: str
    pii_type: str
    match_count: int
    units_with_pii: int
    units_scanned: int
    confidence_band: str
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class DatabaseColumnResult:
    location_locator: str
    field_locator: str
    items: tuple[DatabaseInventoryAggregate, ...]
    units_scanned: int
    bytes_scanned: int


def resolve_postgres_target(
    *,
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    tls_mode: str,
    schemas: tuple[str, ...],
    allowed_hosts: str | None,
    allow_insecure_tls: bool,
) -> PostgresTarget:
    allowed = {
        item.strip().lower().rstrip(".")
        for item in (allowed_hosts or "").split(",")
        if item.strip()
    }
    normalized_host = host.strip().lower().rstrip(".")
    if not allowed:
        raise PostgresScanError(
            "database_hosts_not_configured", "Allowed database hosts are not configured"
        )
    if normalized_host not in allowed:
        raise PostgresScanError(
            "database_host_not_allowed", "Database host is not allowed"
        )
    if tls_mode != "verify-full" and not allow_insecure_tls:
        raise PostgresScanError(
            "insecure_tls_not_allowed",
            "Target TLS verification weakening is disabled",
        )
    try:
        addresses = sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(
                    normalized_host, port, type=socket.SOCK_STREAM
                )
            }
        )
    except OSError as error:
        raise PostgresScanError(
            "database_host_unavailable", "Database host cannot be resolved"
        ) from error
    if not addresses:
        raise PostgresScanError(
            "database_host_unavailable", "Database host cannot be resolved"
        )
    return PostgresTarget(
        host=normalized_host,
        hostaddr=addresses[0],
        port=port,
        database=database,
        username=username,
        password=password,
        tls_mode=tls_mode,
        schemas=schemas,
    )


def _confidence_band(confidence: float) -> str:
    if confidence >= 0.95:
        return "high"
    if confidence >= 0.8:
        return "medium"
    return "low"


def _permission_status(cursor, schemas: tuple[str, ...]) -> str:
    cursor.execute(
        """
        SELECT r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication
            OR r.rolbypassrls
            OR has_database_privilege(current_user, current_database(), 'CREATE')
            OR EXISTS (
                SELECT FROM pg_namespace n
                WHERE n.nspname = ANY(%s)
                  AND has_schema_privilege(current_user, n.oid, 'CREATE')
            )
            OR EXISTS (
                SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = ANY(%s) AND c.relkind IN ('r', 'p')
                  AND has_table_privilege(
                      current_user, c.oid,
                      'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES'
                  )
            )
        FROM pg_roles r WHERE r.rolname = current_user
        """,
        (list(schemas), list(schemas)),
    )
    return "overprivileged" if cursor.fetchone()[0] else "verified_limited"


def _discover_columns(cursor, schemas: tuple[str, ...]):
    cursor.execute(
        """
        SELECT n.nspname, c.relname, a.attname, t.typcategory, t.typname,
               t.typtype
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_type t ON t.oid = a.atttypid
        WHERE n.nspname = ANY(%s)
          AND c.relkind IN ('r', 'p') AND NOT c.relispartition
          AND a.attnum > 0 AND NOT a.attisdropped
          AND has_column_privilege(current_user, c.oid, a.attnum, 'SELECT')
        ORDER BY n.nspname, c.relname, a.attnum
        """,
        (list(schemas),),
    )
    rows = cursor.fetchall()
    supported = [
        row
        for row in rows
        if row[3] == "S" or row[4] in {"json", "jsonb"} or row[5] == "e"
    ]
    return supported, len(rows) - len(supported)


def _scan_column(
    connection, column, detectors, index: int, deadline: float
) -> DatabaseColumnResult:
    schema, table, name, *_ = column
    query = sql.SQL("SELECT {} FROM {}.{}").format(
        sql.Identifier(name), sql.Identifier(schema), sql.Identifier(table)
    )
    aggregates: dict[str, dict[str, object]] = {}
    units = bytes_scanned = 0
    with connection.cursor(name=f"dpmap_scan_{index}") as cursor:
        cursor.itersize = ROW_BATCH_SIZE
        cursor.execute(query)
        for (value,) in cursor:
            if time.monotonic() >= deadline:
                raise PostgresScanError(
                    "target_timeout", "Target scan exceeded its time limit"
                )
            units += 1
            if value is None:
                continue
            source = (
                json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                if isinstance(value, (dict, list))
                else str(value)
            )
            bytes_scanned += len(source.encode("utf-8"))
            summary = aggregate_chunks([source], enabled=detectors, context=name)
            for pii_type, match in summary["matches"].items():
                item = aggregates.setdefault(
                    pii_type,
                    {"matches": 0, "units": 0, "confidence": 0.0, "reasons": set()},
                )
                item["matches"] += match["match_count"]
                item["units"] += 1
                item["confidence"] = max(item["confidence"], match["confidence"])
                item["reasons"].update(match["reason_codes"])
    items = tuple(
        DatabaseInventoryAggregate(
            field_locator=name,
            pii_type=pii_type,
            match_count=item["matches"],
            units_with_pii=item["units"],
            units_scanned=units,
            confidence_band=_confidence_band(item["confidence"]),
            reason_codes=tuple(sorted(item["reasons"])),
        )
        for pii_type, item in sorted(aggregates.items())
    )
    return DatabaseColumnResult(
        location_locator=f"{schema}.{table}",
        field_locator=name,
        items=items,
        units_scanned=units,
        bytes_scanned=bytes_scanned,
    )


def scan_postgres(
    target: PostgresTarget,
    detectors: frozenset[str],
    emit: Callable[[DatabaseColumnResult], None],
) -> tuple[str, int]:
    """Scan selected schemas and emit aggregate-only column results."""
    deadline = time.monotonic() + TOTAL_JOB_TIMEOUT_SECONDS
    try:
        with psycopg.connect(
            host=target.host,
            hostaddr=target.hostaddr,
            port=target.port,
            dbname=target.database,
            user=target.username,
            password=target.password,
            sslmode=target.tls_mode,
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
            autocommit=True,
            application_name="dpmap-readonly-scan",
            options=(
                f"-c statement_timeout={STATEMENT_TIMEOUT_MS} "
                f"-c idle_in_transaction_session_timeout={IDLE_TRANSACTION_TIMEOUT_MS}"
            ),
        ) as connection:
            connection.read_only = True
            with connection.transaction(force_rollback=True):
                with connection.cursor() as cursor:
                    cursor.execute("SELECT current_setting('transaction_read_only')")
                    if cursor.fetchone()[0] != "on":
                        raise PostgresScanError(
                            "read_only_not_enforced",
                            "Target read-only transaction could not be enforced",
                        )
                    permission = _permission_status(cursor, target.schemas)
                    columns, unsupported = _discover_columns(cursor, target.schemas)
                for index, column in enumerate(columns):
                    if time.monotonic() >= deadline:
                        raise PostgresScanError(
                            "target_timeout", "Target scan exceeded its time limit"
                        )
                    emit(
                        _scan_column(
                            connection, column, detectors, index, deadline
                        )
                    )
        return permission, unsupported
    except PostgresScanError:
        raise
    except psycopg.errors.QueryCanceled as error:
        raise PostgresScanError(
            "target_timeout", "Target query exceeded its time limit"
        ) from error
    except psycopg.OperationalError as error:
        raise PostgresScanError(
            "target_access_failed", "Target database connection failed"
        ) from error
    except psycopg.DatabaseError as error:
        raise PostgresScanError(
            "target_scan_failed", "Target database scan failed"
        ) from error
