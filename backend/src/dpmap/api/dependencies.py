"""Authentication and authorization dependencies."""

from dataclasses import dataclass
from typing import Annotated, Callable

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from dpmap.api.errors import ApiError
from dpmap.core.security import decode_access_token, get_jwt_secret, utc_now
from dpmap.db.models import AuthSession, User
from dpmap.db.session import get_session


bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthPrincipal:
    user: User
    auth_session: AuthSession
    database: Session


def _authentication_required() -> ApiError:
    return ApiError(
        status_code=401,
        code="authentication_required",
        message="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    database: Annotated[Session, Depends(get_session)],
) -> AuthPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _authentication_required()
    claims = decode_access_token(credentials.credentials, get_jwt_secret())
    if claims is None:
        raise _authentication_required()
    auth_session = database.get(AuthSession, claims.jti)
    user = database.get(User, claims.user_id)
    if (
        auth_session is None
        or auth_session.user_id != claims.user_id
        or auth_session.revoked_at is not None
        or auth_session.expires_at <= utc_now()
        or user is None
        or not user.is_active
    ):
        raise _authentication_required()
    return AuthPrincipal(user=user, auth_session=auth_session, database=database)


def require_roles(*allowed_roles: str) -> Callable[[AuthPrincipal], AuthPrincipal]:
    def authorize(
        principal: Annotated[AuthPrincipal, Depends(get_principal)],
    ) -> AuthPrincipal:
        if principal.user.role not in allowed_roles:
            raise ApiError(status_code=403, code="forbidden", message="Forbidden")
        return principal

    return authorize
