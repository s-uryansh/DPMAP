"""FastAPI application entry point."""

from fastapi import FastAPI

from dpmap import __version__
from dpmap.api.errors import ApiError, api_error_handler
from dpmap.api.routes.auth import router as auth_router
from dpmap.api.routes.scans import router as scans_router


def create_app() -> FastAPI:
    application = FastAPI(title="DPMAP", version=__version__)
    application.add_exception_handler(ApiError, api_error_handler)
    application.include_router(auth_router)
    application.include_router(scans_router)

    @application.get("/health")
    def health_check() -> dict[str, str]:
        return health()

    return application


def health() -> dict[str, str]:
    """Return process liveness without exposing configuration or secrets."""
    return {"status": "ok", "version": __version__}


app = create_app()
