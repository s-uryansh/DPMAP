from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from dpmap.api.dependencies import require_roles
from dpmap.api.errors import ApiError
from dpmap.api.schemas import (
    BatchCreateRequest,
    DirectoryScanRequest,
    LoginRequest,
    MySQLScanRequest,
    PostgresScanRequest,
)
from dpmap.core.security import (
    decode_access_token,
    get_jwt_secret,
    hash_password,
    password_needs_rehash,
    verify_password,
)
from dpmap.db.session import _session_factory, get_session


def test_security_boundaries_reject_invalid_input(monkeypatch) -> None:
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        get_jwt_secret()
    with pytest.raises(ValueError, match="between 15 and 1024"):
        hash_password("too-short")
    assert not password_needs_rehash(hash_password("long-enough-password"))
    assert not verify_password("anything", "not-an-argon-hash")
    assert decode_access_token("not-a-token", "x" * 32) is None

    with pytest.raises(ValidationError):
        LoginRequest(email="invalid", password="long-enough-password")
    with pytest.raises(ValidationError, match="detectors must be unique"):
        DirectoryScanRequest(
            label="test",
            target_name="test",
            path="/tmp/test",
            detectors=["email", "email"],
        )
    postgres_request = {
        "label": "test",
        "target_name": "test",
        "host": "db.example.test",
        "port": 5432,
        "database": "records",
        "username": "reader",
        "password": "request-only-secret",
        "schemas": ["public"],
        "detectors": ["email"],
    }
    with pytest.raises(ValidationError, match="schemas must be unique"):
        PostgresScanRequest(**(postgres_request | {"schemas": ["x", "x"]}))
    with pytest.raises(ValidationError, match="invalid schema"):
        PostgresScanRequest(**(postgres_request | {"schemas": ["x\x00y"]}))
    with pytest.raises(ValidationError, match="detectors must be unique"):
        PostgresScanRequest(
            **(postgres_request | {"detectors": ["email", "email"]})
        )
    mysql_request = postgres_request | {"port": 3306}
    mysql_request.pop("schemas")
    with pytest.raises(ValidationError, match="detectors must be unique"):
        MySQLScanRequest(
            **(mysql_request | {"detectors": ["email", "email"]})
        )
    batch_target = {
        "client_ref": "db",
        "target_name": "Database",
        "type": "database",
        "database": mysql_request | {"engine": "mysql"},
        "scope": {"schemas": ["public"]},
        "detectors": ["email"],
    }
    batch_target["database"].pop("label")
    batch_target["database"].pop("target_name")
    batch_target["database"].pop("detectors")
    with pytest.raises(ValidationError, match="schemas must be unique"):
        BatchCreateRequest(
            label="batch",
            targets=[batch_target | {"scope": {"schemas": ["x", "x"]}}],
        )
    with pytest.raises(ValidationError, match="invalid schema"):
        BatchCreateRequest(
            label="batch",
            targets=[batch_target | {"scope": {"schemas": ["x\x00y"]}}],
        )
    with pytest.raises(ValidationError, match="detectors must be unique"):
        BatchCreateRequest(
            label="batch",
            targets=[batch_target | {"detectors": ["email", "email"]}],
        )
    with pytest.raises(ValidationError, match="client_ref values must be unique"):
        BatchCreateRequest(label="batch", targets=[batch_target, batch_target])

    authorize = require_roles("admin", "auditor")
    viewer = SimpleNamespace(user=SimpleNamespace(role="viewer"))
    with pytest.raises(ApiError) as error:
        authorize(viewer)
    assert error.value.status_code == 403

    monkeypatch.delenv("APP_DB_URL", raising=False)
    with pytest.raises(RuntimeError, match="APP_DB_URL is required"):
        next(get_session())

    monkeypatch.setenv("APP_DB_URL", "sqlite://")
    database = get_session()
    assert next(database).bind.dialect.name == "sqlite"
    database.close()
    _session_factory.cache_clear()
