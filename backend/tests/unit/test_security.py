from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from dpmap.api.dependencies import require_roles
from dpmap.api.errors import ApiError
from dpmap.api.schemas import LoginRequest
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
