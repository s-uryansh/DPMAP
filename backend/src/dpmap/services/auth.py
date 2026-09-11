"""Authentication use cases."""

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from dpmap.core.security import (
    ACCESS_TOKEN_TTL,
    DUMMY_PASSWORD_HASH,
    encode_access_token,
    hash_password,
    password_needs_rehash,
    utc_now,
    verify_password,
)
from dpmap.db.models import AuditEvent, AuthSession, User


@dataclass(frozen=True)
class LoginResult:
    access_token: str
    expires_at: datetime
    user: User


class InvalidCredentialsError(Exception):
    pass


def authenticate(
    session: Session, email: str, password: str, secret: str
) -> LoginResult:
    normalized_email = email.strip().lower()
    user = session.scalar(select(User).where(User.email == normalized_email))
    if user is None:
        verify_password(password, DUMMY_PASSWORD_HASH)
        raise InvalidCredentialsError
    if not verify_password(password, user.password_hash) or not user.is_active:
        raise InvalidCredentialsError

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    issued_at = utc_now()
    expires_at = issued_at + ACCESS_TOKEN_TTL
    jti = uuid4()
    session.add(AuthSession(id=jti, user_id=user.id, expires_at=expires_at))
    session.add(
        AuditEvent(
            id=uuid4(),
            actor_user_id=user.id,
            action="auth.login",
            object_type="auth_session",
            object_id=jti,
        )
    )
    session.commit()
    return LoginResult(
        access_token=encode_access_token(
            user_id=user.id,
            jti=jti,
            secret=secret,
            issued_at=issued_at,
            expires_at=expires_at,
        ),
        expires_at=expires_at,
        user=user,
    )


def revoke_session(session: Session, auth_session: AuthSession, user: User) -> None:
    auth_session.revoked_at = utc_now()
    session.add(
        AuditEvent(
            id=uuid4(),
            actor_user_id=user.id,
            action="auth.logout",
            object_type="auth_session",
            object_id=auth_session.id,
        )
    )
    session.commit()


def bootstrap_admin(session: Session, email: str, password: str) -> User:
    """Create the first Admin only; the password is hashed before `add`."""
    session.execute(text("LOCK TABLE users IN ACCESS EXCLUSIVE MODE"))
    if session.scalar(select(func.count()).select_from(User)):
        raise RuntimeError("application is already initialized")
    normalized_email = email.strip().lower()
    if normalized_email.count("@") != 1 or len(normalized_email) > 320:
        raise ValueError("invalid email")
    user = User(
        id=uuid4(),
        email=normalized_email,
        role="admin",
        password_hash=hash_password(password),
    )
    session.add(user)
    session.commit()
    return user
