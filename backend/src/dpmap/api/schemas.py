"""API request and response schemas."""

from datetime import datetime
from typing import Annotated, Literal
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


class MySQLScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=200)
    target_name: str = Field(min_length=1, max_length=200)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=3306, ge=1, le=65535)
    database: str = Field(min_length=1, max_length=64, pattern=r"^[^\x00/]+$")
    username: str = Field(min_length=1, max_length=32, pattern=r"^[^\x00]+$")
    password: SecretStr = Field(min_length=1, max_length=1024)
    tls_mode: Literal[
        "verify-identity", "verify-ca", "required", "disable"
    ] = "verify-identity"
    detectors: list[DetectorName] = Field(min_length=1)

    @field_validator("detectors")
    @classmethod
    def unique_mysql_detectors(
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


class BatchPostgresDatabase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engine: Literal["postgresql"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = Field(min_length=1, max_length=63, pattern=r"^[^\x00/]+$")
    username: str = Field(min_length=1, max_length=63, pattern=r"^[^\x00]+$")
    password: SecretStr = Field(min_length=1, max_length=1024)
    tls_mode: Literal["verify-full", "require", "disable"] = "verify-full"


class BatchMySQLDatabase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engine: Literal["mysql"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=3306, ge=1, le=65535)
    database: str = Field(min_length=1, max_length=64, pattern=r"^[^\x00/]+$")
    username: str = Field(min_length=1, max_length=32, pattern=r"^[^\x00]+$")
    password: SecretStr = Field(min_length=1, max_length=1024)
    tls_mode: Literal[
        "verify-identity", "verify-ca", "required", "disable"
    ] = "verify-identity"


BatchDatabase = Annotated[
    BatchPostgresDatabase | BatchMySQLDatabase,
    Field(discriminator="engine"),
]


class BatchDatabaseScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemas: list[str] = Field(default=["public"], min_length=1, max_length=32)

    @field_validator("schemas")
    @classmethod
    def valid_schemas(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("schemas must be unique")
        if any(not item or "\x00" in item or len(item) > 63 for item in value):
            raise ValueError("invalid schema")
        return value


class BatchDirectoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=4096)


class BatchTargetBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_ref: str = Field(min_length=1, max_length=200)
    target_name: str = Field(min_length=1, max_length=200)
    detectors: list[DetectorName] = Field(min_length=1)
    governance_context: dict[str, object] = Field(default_factory=dict)
    control_evidence: dict[str, object] = Field(default_factory=dict)

    @field_validator("detectors")
    @classmethod
    def unique_batch_detectors(
        cls, value: list[DetectorName]
    ) -> list[DetectorName]:
        if len(value) != len(set(value)):
            raise ValueError("detectors must be unique")
        return value


class BatchDirectoryTarget(BatchTargetBase):
    type: Literal["directory"]
    directory: BatchDirectoryConfig


class BatchDatabaseTarget(BatchTargetBase):
    type: Literal["database"]
    database: BatchDatabase
    scope: BatchDatabaseScope = Field(default_factory=BatchDatabaseScope)


BatchTarget = Annotated[
    BatchDirectoryTarget | BatchDatabaseTarget,
    Field(discriminator="type"),
]


class BatchCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=200)
    targets: list[BatchTarget] = Field(min_length=1, max_length=20)

    @field_validator("targets")
    @classmethod
    def unique_client_refs(cls, value: list[BatchTarget]) -> list[BatchTarget]:
        refs = [target.client_ref for target in value]
        if len(refs) != len(set(refs)):
            raise ValueError("client_ref values must be unique")
        return value


class BatchCreateJobResponse(BaseModel):
    job_id: UUID
    client_ref: str
    status: str
    status_url: str


class BatchCreateResponse(BaseModel):
    batch_id: UUID
    jobs: list[BatchCreateJobResponse]
    batch_status_url: str


class BatchJobStatusResponse(JobStatusResponse):
    target_name: str
    target_type: str
    target_engine: str | None


class BatchStatusResponse(BaseModel):
    batch_id: UUID
    status: str
    jobs: list[BatchJobStatusResponse]
