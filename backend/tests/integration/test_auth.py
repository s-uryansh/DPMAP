import asyncio
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi import Depends
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from dpmap.api.dependencies import AuthPrincipal, require_roles
from dpmap.core.security import encode_access_token, hash_password
from dpmap.db.models import AuditEvent, AuthSession, User
from dpmap.db.session import get_session
from dpmap.main import create_app
from dpmap.services.auth import bootstrap_admin


BACKEND_ROOT = Path(__file__).parents[2]


def _alembic_config(database_url: str) -> Config:
    config = Config(BACKEND_ROOT / "alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


async def _asgi_request(app, method, path, payload=None, token=None):
    body = json.dumps(payload).encode() if payload is not None else b""
    headers = [(b"content-type", b"application/json")]
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    messages = []
    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    await app(scope, receive, send)
    start = next(
        message
        for message in messages
        if message["type"] == "http.response.start"
    )
    response_body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    return start["status"], json.loads(response_body) if response_body else None


def _request(app, method, path, payload=None, token=None):
    return asyncio.run(_asgi_request(app, method, path, payload, token))


def test_authentication_and_role_contract(monkeypatch) -> None:
    database_url = os.getenv("TEST_APP_DB_URL")
    if not database_url:
        pytest.skip("TEST_APP_DB_URL is required for authentication tests")

    jwt_secret = secrets.token_urlsafe(48)
    admin_password = secrets.token_urlsafe(24)
    auditor_password = secrets.token_urlsafe(24)
    monkeypatch.setenv("JWT_SECRET", jwt_secret)
    rehash_results = iter((True, False))
    monkeypatch.setattr(
        "dpmap.services.auth.password_needs_rehash", lambda _: next(rehash_results)
    )

    config = _alembic_config(database_url)
    engine = create_engine(database_url)
    session_factory = sessionmaker(engine, expire_on_commit=False)
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    def override_session():
        with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_session] = override_session

    @app.get("/_test/export")
    def protected_export(
        principal: AuthPrincipal = Depends(require_roles("admin", "auditor")),
    ):
        return {"role": principal.user.role}

    try:
        with session_factory() as session:
            with pytest.raises(ValueError, match="invalid email"):
                bootstrap_admin(session, "invalid", admin_password)
            admin = bootstrap_admin(session, "ADMIN@EXAMPLE.TEST", admin_password)
            assert admin.email == "admin@example.test"
            assert admin.password_hash != admin_password
            with pytest.raises(RuntimeError, match="already initialized"):
                bootstrap_admin(session, "other@example.test", admin_password)

            auditor = User(
                id=uuid4(),
                email="auditor@example.test",
                role="auditor",
                password_hash=hash_password(auditor_password),
            )
            session.add(auditor)
            session.commit()

        wrong_password = secrets.token_urlsafe(16)
        wrong = _request(
            app,
            "POST",
            "/api/v1/auth/login",
            {"email": "admin@example.test", "password": wrong_password},
        )
        missing = _request(
            app,
            "POST",
            "/api/v1/auth/login",
            {"email": "missing@example.test", "password": secrets.token_urlsafe(16)},
        )
        assert wrong[0] == missing[0] == 401
        assert wrong[1]["code"] == missing[1]["code"] == "invalid_credentials"
        assert wrong_password not in json.dumps(wrong[1])

        admin_login = _request(
            app,
            "POST",
            "/api/v1/auth/login",
            {"email": "ADMIN@example.test", "password": admin_password},
        )
        assert admin_login[0] == 200
        admin_token = admin_login[1]["access_token"]
        assert admin_login[1]["token_type"] == "bearer"
        assert admin_login[1]["user"]["role"] == "admin"

        auditor_login = _request(
            app,
            "POST",
            "/api/v1/auth/login",
            {"email": "auditor@example.test", "password": auditor_password},
        )
        assert auditor_login[0] == 200
        auditor_token = auditor_login[1]["access_token"]

        assert _request(app, "GET", "/_test/export", token=admin_token) == (
            200,
            {"role": "admin"},
        )
        assert _request(app, "GET", "/_test/export", token=auditor_token) == (
            200,
            {"role": "auditor"},
        )
        assert _request(app, "GET", "/_test/export")[0] == 401

        assert _request(app, "POST", "/api/v1/auth/logout", token=admin_token)[0] == 204
        assert _request(app, "GET", "/_test/export", token=admin_token)[0] == 401

        now = datetime.now(timezone.utc)
        expired_jti = uuid4()
        with session_factory() as session:
            session.add(
                AuthSession(
                    id=expired_jti,
                    user_id=admin.id,
                    created_at=now - timedelta(hours=2),
                    expires_at=now - timedelta(hours=1),
                )
            )
            session.commit()
        expired_token = encode_access_token(
            user_id=admin.id,
            jti=expired_jti,
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            secret=jwt_secret,
        )
        assert _request(app, "GET", "/_test/export", token=expired_token)[0] == 401

        with session_factory() as session:
            stored_auditor = session.get(User, auditor.id)
            stored_auditor.is_active = False
            session.commit()
        assert _request(app, "GET", "/_test/export", token=auditor_token)[0] == 401
        inactive_login = _request(
            app,
            "POST",
            "/api/v1/auth/login",
            {"email": "auditor@example.test", "password": auditor_password},
        )
        assert inactive_login[0] == 401

        with session_factory() as session:
            actions = list(session.scalars(select(AuditEvent.action)))
            assert actions.count("auth.login") == 2
            assert actions.count("auth.logout") == 1
            for details in session.scalars(select(AuditEvent.details_json)):
                serialized = json.dumps(details)
                assert admin_password not in serialized
                assert auditor_password not in serialized
    finally:
        app.dependency_overrides.clear()
        command.downgrade(config, "base")
        engine.dispose()
