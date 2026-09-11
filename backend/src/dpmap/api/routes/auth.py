"""Authentication routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from dpmap.api.dependencies import AuthPrincipal, get_principal
from dpmap.api.errors import ApiError
from dpmap.api.schemas import LoginRequest, LoginResponse, UserResponse
from dpmap.core.security import get_jwt_secret
from dpmap.db.session import get_session
from dpmap.services.auth import InvalidCredentialsError, authenticate, revoke_session


router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
def login(
    request: LoginRequest,
    database: Annotated[Session, Depends(get_session)],
) -> LoginResponse:
    try:
        result = authenticate(
            database,
            request.email,
            request.password.get_secret_value(),
            get_jwt_secret(),
        )
    except InvalidCredentialsError as error:
        raise ApiError(
            status_code=401,
            code="invalid_credentials",
            message="Invalid email or password",
        ) from error
    return LoginResponse(
        access_token=result.access_token,
        expires_at=result.expires_at,
        user=UserResponse.model_validate(result.user),
    )


@router.post("/logout", status_code=204)
def logout(principal: Annotated[AuthPrincipal, Depends(get_principal)]) -> Response:
    revoke_session(principal.database, principal.auth_session, principal.user)
    return Response(status_code=204)
