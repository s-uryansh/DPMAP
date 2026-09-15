"""API request and response schemas."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    password: SecretStr = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized.count("@") != 1:
            raise ValueError("invalid email")
        return normalized


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    role: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: UserResponse


DetectorName = Literal["pan", "aadhaar", "phone", "email", "person_name"]


class DirectoryScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=200)
    target_name: str = Field(min_length=1, max_length=200)
    path: str = Field(min_length=1, max_length=4096)
    detectors: list[DetectorName] = Field(min_length=1)

    @field_validator("detectors")
    @classmethod
    def unique_detectors(cls, value: list[DetectorName]) -> list[DetectorName]:
        if len(value) != len(set(value)):
            raise ValueError("detectors must be unique")
        return value


class DirectoryScanResponse(BaseModel):
    batch_id: UUID
    job_id: UUID
    status: str
    status_url: str


class PostgresScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=200)
    target_name: str = Field(min_length=1, max_length=200)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    database: str = Field(min_length=1, max_length=63, pattern=r"^[^\x00/]+$")
    username: str = Field(min_length=1, max_length=63, pattern=r"^[^\x00]+$")
    password: SecretStr = Field(min_length=1, max_length=1024)
    tls_mode: Literal["verify-full", "require", "disable"] = "verify-full"
    schemas: list[str] = Field(default=["public"], min_length=1, max_length=32)
    detectors: list[DetectorName] = Field(min_length=1)

    @field_validator("schemas")
    @classmethod
    def unique_schemas(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("schemas must be unique")
        if any(not schema or "\x00" in schema or len(schema) > 63 for schema in value):
            raise ValueError("invalid schema")
        return value

    @field_validator("detectors")
    @classmethod
    def unique_postgres_detectors(
        cls, value: list[DetectorName]
    ) -> list[DetectorName]:
        if len(value) != len(set(value)):
            raise ValueError("detectors must be unique")
        return value


class JobStatusResponse(BaseModel):
    job_id: UUID
    status: str
    stage: str | None
    progress_percent: int
    matches_found: int
    units_scanned: int
    bytes_scanned: int
    locations_scanned: int
    permission_check_status: str
    coverage_status: str
    error_code: str | None
    error_message: str | None
