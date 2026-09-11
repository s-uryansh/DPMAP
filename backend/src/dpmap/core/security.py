"""Password and access-token primitives.

JWT signing secrets are read from the process environment and remain in memory.
Passwords are converted to Argon2id hashes before any database write.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError


JWT_ALGORITHM = "HS256"
JWT_ISSUER = "dpmap"
JWT_AUDIENCE = "dpmap-api"
ACCESS_TOKEN_TTL = timedelta(minutes=15)
PASSWORD_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19 * 1024,
    parallelism=1,
    type=Type.ID,
)
DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash("dpmap-dummy-password-not-an-account")


@dataclass(frozen=True)
class TokenClaims:
    user_id: UUID
    jti: UUID


def get_jwt_secret() -> str:
    """Load the signing secret without caching, logging, or disk persistence."""
    secret = os.getenv("JWT_SECRET", "")
    if len(secret.encode()) < 32:
        raise RuntimeError("JWT_SECRET must contain at least 32 bytes")
    return secret


def hash_password(password: str) -> str:
    if not 15 <= len(password) <= 1024:
        raise ValueError("password must contain between 15 and 1024 characters")
    return PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerificationError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return PASSWORD_HASHER.check_needs_rehash(password_hash)


def encode_access_token(
    *,
    user_id: UUID,
    jti: UUID,
    secret: str,
    issued_at: datetime,
    expires_at: datetime,
) -> str:
    payload = {
        "sub": str(user_id),
        "jti": str(jti),
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str, secret: str) -> TokenClaims | None:
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={
                "require": ["sub", "jti", "iat", "nbf", "exp", "iss", "aud"],
                "strict_aud": True,
            },
        )
        return TokenClaims(user_id=UUID(payload["sub"]), jti=UUID(payload["jti"]))
    except (jwt.InvalidTokenError, ValueError, TypeError):
        return None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
