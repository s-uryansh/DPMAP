"""Bounded MySQL 8.4 scanning with enforced read-only transactions."""

from dataclasses import dataclass, field
import json
import socket
import time
from typing import Callable

import mysql.connector
from mysql.connector import errors

from dpmap.engine.detectors import aggregate_chunks
from dpmap.engine.scanners.postgres import (
    DatabaseColumnResult,
    DatabaseInventoryAggregate,
)


CONNECT_TIMEOUT_SECONDS = 5
STATEMENT_TIMEOUT_MS = 5_000
SOCKET_TIMEOUT_SECONDS = 6
TOTAL_JOB_TIMEOUT_SECONDS = 60
ROW_BATCH_SIZE = 256
SUPPORTED_TYPES = frozenset(
    {
        "char",
        "enum",
        "json",
        "longtext",
        "mediumtext",
        "set",
        "text",
        "tinytext",
        "varchar",
    }
)
WRITE_PRIVILEGES = frozenset(
    {
        "ALTER",
        "ALTER ROUTINE",
        "CREATE",
        "CREATE ROLE",
        "CREATE ROUTINE",
        "CREATE TABLESPACE",
        "CREATE TEMPORARY TABLES",
        "CREATE USER",
        "CREATE VIEW",
        "DELETE",
        "DROP",
        "DROP ROLE",
        "EVENT",
        "EXECUTE",
        "FILE",
        "GRANT OPTION",
        "INDEX",
        "INSERT",
        "LOCK TABLES",
        "REFERENCES",
        "RELOAD",
        "REPLICATION SLAVE",
        "REPLICATION CLIENT",
        "SHUTDOWN",
        "SUPER",
        "TRIGGER",
        "UPDATE",
    }
)


class MySQLScanError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MySQLTarget:
    host: str
    hostaddr: str
    port: int
    database: str
    username: str
    password: str = field(repr=False)
    tls_mode: str = "verify-identity"
    ssl_ca: str | None = None


def resolve_mysql_target(
    *,
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    tls_mode: str,
    ssl_ca: str | None,
    allowed_hosts: str | None,
    allow_insecure_tls: bool,
) -> MySQLTarget:
    allowed = {
        item.strip().lower().rstrip(".")
        for item in (allowed_hosts or "").split(",")
        if item.strip()
    }
    normalized_host = host.strip().lower().rstrip(".")
    if not allowed:
        raise MySQLScanError(
            "database_hosts_not_configured", "Allowed database hosts are not configured"
        )
    if normalized_host not in allowed:
        raise MySQLScanError(
            "database_host_not_allowed", "Database host is not allowed"
        )
    if tls_mode != "verify-identity" and not allow_insecure_tls:
        raise MySQLScanError(
            "insecure_tls_not_allowed",
            "Target TLS verification weakening is disabled",
        )
    if tls_mode in {"verify-identity", "verify-ca"} and not ssl_ca:
        raise MySQLScanError(
            "mysql_tls_ca_required", "A MySQL CA file is required for TLS verification"
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
        raise MySQLScanError(
            "database_host_unavailable", "Database host cannot be resolved"
        ) from error
    if not addresses:
        raise MySQLScanError(
            "database_host_unavailable", "Database host cannot be resolved"
        )
    return MySQLTarget(
        normalized_host,
        addresses[0],
        port,
        database,
        username,
        password,
        tls_mode,
        ssl_ca,
    )


def _identifier(value: str) -> str:
    return f"`{value.replace('`', '``')}`"


def _confidence_band(confidence: float) -> str:
    if confidence >= 0.95:
        return "high"
    if confidence >= 0.8:
        return "medium"
    return "low"


def _permission_status(cursor, database: str) -> str:
    cursor.execute(
        """
        SELECT 'GLOBAL', PRIVILEGE_TYPE, IS_GRANTABLE
        FROM INFORMATION_SCHEMA.USER_PRIVILEGES
        WHERE GRANTEE = CONCAT(
            QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', 1)), '@',
            QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', -1))
        )
        UNION ALL
        SELECT 'SCHEMA', PRIVILEGE_TYPE, IS_GRANTABLE
        FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES
        WHERE GRANTEE = CONCAT(
            QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', 1)), '@',
            QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', -1))
        ) AND TABLE_SCHEMA = %s
        UNION ALL
        SELECT 'TABLE', PRIVILEGE_TYPE, IS_GRANTABLE
        FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES
        WHERE GRANTEE = CONCAT(
            QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', 1)), '@',
            QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', -1))
        ) AND TABLE_SCHEMA = %s
        UNION ALL
        SELECT 'COLUMN', PRIVILEGE_TYPE, IS_GRANTABLE
        FROM INFORMATION_SCHEMA.COLUMN_PRIVILEGES
        WHERE GRANTEE = CONCAT(
            QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', 1)), '@',
            QUOTE(SUBSTRING_INDEX(CURRENT_USER(), '@', -1))
        ) AND TABLE_SCHEMA = %s
        """,
        (database, database, database),
    )
    privileges = cursor.fetchall()
    return (
        "overprivileged"
        if any(
            (scope == "GLOBAL" and privilege != "USAGE")
            or privilege in WRITE_PRIVILEGES
            or grantable == "YES"
            for scope, privilege, grantable in privileges
        )
        else "verified_limited"
    )


def _discover_columns(cursor, database: str):
    cursor.execute(
        """
        SELECT c.TABLE_SCHEMA, c.TABLE_NAME, c.COLUMN_NAME, c.DATA_TYPE
        FROM INFORMATION_SCHEMA.COLUMNS c
        JOIN INFORMATION_SCHEMA.TABLES t
          ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME
        WHERE c.TABLE_SCHEMA = %s AND t.TABLE_TYPE = 'BASE TABLE'
        ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION
        """,
        (database,),
    )
    rows = cursor.fetchall()
    supported = [row for row in rows if row[3].lower() in SUPPORTED_TYPES]
    return supported, len(rows) - len(supported)


def _scan_column(
    connection, column, detectors, deadline: float
) -> DatabaseColumnResult:
    database, table, name, _ = column
    query = (
        f"SELECT /*+ MAX_EXECUTION_TIME({STATEMENT_TIMEOUT_MS}) */ "
        f"{_identifier(name)} FROM {_identifier(database)}.{_identifier(table)}"
    )
    aggregates: dict[str, dict[str, object]] = {}
    units = bytes_scanned = 0
    cursor = connection.cursor(buffered=False)
    try:
        cursor.execute(query)
        while rows := cursor.fetchmany(ROW_BATCH_SIZE):
            for (value,) in rows:
                if time.monotonic() >= deadline:
                    raise MySQLScanError(
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
                        {
                            "matches": 0,
                            "units": 0,
                            "confidence": 0.0,
                            "reasons": set(),
                        },
                    )
                    item["matches"] += match["match_count"]
                    item["units"] += 1
                    item["confidence"] = max(
                        item["confidence"], match["confidence"]
                    )
                    item["reasons"].update(match["reason_codes"])
    finally:
        cursor.close()
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
        location_locator=f"{database}.{table}",
        field_locator=name,
        items=items,
        units_scanned=units,
        bytes_scanned=bytes_scanned,
    )


def _tls_options(target: MySQLTarget) -> dict[str, object]:
    if target.tls_mode == "disable":
        return {"ssl_disabled": True}
    options: dict[str, object] = {"ssl_disabled": False}
    if target.ssl_ca:
        options["ssl_ca"] = target.ssl_ca
    if target.tls_mode in {"verify-ca", "verify-identity"}:
        options["ssl_verify_cert"] = True
    if target.tls_mode == "verify-identity":
        options["ssl_verify_identity"] = True
    return options


def scan_mysql(
    target: MySQLTarget,
    detectors: frozenset[str],
    emit: Callable[[DatabaseColumnResult], None],
) -> tuple[str, int]:
    """Scan the selected database and emit aggregate-only column results."""
    deadline = time.monotonic() + TOTAL_JOB_TIMEOUT_SECONDS
    connection = None
    try:
        connection = mysql.connector.connect(
            host=target.hostaddr,
            port=target.port,
            database=target.database,
            user=target.username,
            password=target.password,
            connection_timeout=CONNECT_TIMEOUT_SECONDS,
            read_timeout=SOCKET_TIMEOUT_SECONDS,
            write_timeout=SOCKET_TIMEOUT_SECONDS,
            buffered=False,
            use_pure=True,
            conn_attrs={"program_name": "dpmap-readonly-scan"},
            **_tls_options(target),
        )
        with connection.cursor(buffered=True) as cursor:
            cursor.execute(
                "SET SESSION TRANSACTION READ ONLY /* dpmap-readonly-scan */"
            )
        connection.start_transaction(readonly=True)
        with connection.cursor(buffered=True) as cursor:
            cursor.execute("SELECT @@SESSION.transaction_read_only")
            if cursor.fetchone()[0] != 1:
                raise MySQLScanError(
                    "read_only_not_enforced",
                    "Target read-only transaction could not be enforced",
                )
            permission = _permission_status(cursor, target.database)
            columns, unsupported = _discover_columns(cursor, target.database)
        for column in columns:
            if time.monotonic() >= deadline:
                raise MySQLScanError(
                    "target_timeout", "Target scan exceeded its time limit"
                )
            emit(_scan_column(connection, column, detectors, deadline))
        return permission, unsupported
    except MySQLScanError:
        raise
    except (errors.ReadTimeoutError, errors.WriteTimeoutError) as error:
        raise MySQLScanError(
            "target_timeout", "Target query exceeded its time limit"
        ) from error
    except errors.Error as error:
        if error.errno in {1044, 1045, 2002, 2003, 2005}:
            code, message = "target_access_failed", "Target database connection failed"
        elif error.errno in {1205, 1317, 3024}:
            code, message = "target_timeout", "Target query exceeded its time limit"
        else:
            code, message = "target_scan_failed", "Target database scan failed"
        raise MySQLScanError(code, message) from error
    finally:
        if connection is not None:
            try:
                connection.rollback()
            except errors.Error:
                pass
            connection.close()
