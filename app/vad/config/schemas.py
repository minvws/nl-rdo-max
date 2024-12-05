from enum import Enum

from pydantic import BaseModel, Field, model_validator

from app.vad.logging.schemas import LogLevel


class JweFactoryType(Enum):
    JOSE = "jose"
    NOOP = "noop"


class AppConfig(BaseModel):
    name: str = Field()
    loglevel: LogLevel = Field(default=LogLevel.INFO)
    uvicorn_app: bool = Field(default=False)
    jwe_factory: JweFactoryType = Field(default=JweFactoryType.NOOP)
    jwe_encryption_key: str | None = Field(default=None)

    @model_validator(mode="after")
    def validate_jwe_encryption_key(self) -> "AppConfig":
        if self.jwe_factory == JweFactoryType.JOSE and not self.jwe_encryption_key:
            raise ValueError("jwe_encryption_key is required when jwe_factory is 'jose'")

        return self


class PrsRepositoryType(Enum):
    MOCK = "mock"
    API = "api"


class PrsConfig(BaseModel):
    prs_repository: PrsRepositoryType
    repo_base_url: str | None
    organisation_id: str

    @model_validator(mode="after")
    def validate_repo_base_url_required(self) -> "PrsConfig":
        if self.prs_repository is PrsRepositoryType.API and not self.repo_base_url:
            raise ValueError("repo_base_url is required when prs_repository is 'api'")

        return self

class BrpConfig(BaseModel):
    mock_brp: bool = Field(default=False)
    base_url: str = Field(default=None)
    api_key: str = Field(default=None)


class Config(BaseModel):
    app: AppConfig
    prs: PrsConfig
    brp: BrpConfig
