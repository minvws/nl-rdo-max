import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture

from app.vad.config.schemas import AppConfig, BrpConfig, Config, JweFactoryType, PrsConfig, PrsRepositoryType
from app.vad.logging.schemas import LogLevel


def test_it_throws_no_error_on_valid_config() -> None:
    Config(
        app=AppConfig(
            name="VAD",
            loglevel=LogLevel.CRITICAL,
            uvicorn_app=False,
            jwe_encryption_key="tests/fixtures/keys/test_jwe_encryption_key.pem",
        ),
        prs=PrsConfig(
            prs_repository=PrsRepositoryType.MOCK,
            repo_base_url="http://localhost:8000",
            organisation_id="123456789",
        ),
        brp=BrpConfig(mock_brp=True),
    )


def test_it_throws_error_on_invalid_config(mocker: MockerFixture) -> None:
    with pytest.raises(ValidationError):
        loglevel = mocker.Mock()

        Config(
            app=AppConfig(name="VAD", loglevel=loglevel, uvicorn_app=False, jwe_encryption_key="non-existing-file"),
            prs=PrsConfig(
                prs_repository=PrsRepositoryType.MOCK,
                repo_base_url="http://localhost:8000",
                organisation_id="123456789",
            ),
            brp=BrpConfig(mock_brp=True),
        )


@pytest.mark.parametrize(
    "base_url, expected_error",
    [
        ("", "repo_base_url is required when prs_repository is 'api'"),
    ],
)
def test_it_requires_base_url_when_using_prs_api_repo(base_url: str, expected_error: str) -> None:
    with pytest.raises(ValidationError) as e:
        Config(
            app=AppConfig(
                name="VAD",
                loglevel=LogLevel.CRITICAL,
                uvicorn_app=False,
                jwe_encryption_key="tests/fixtures/keys/test_jwe_encryption_key.pem",
            ),
            prs=PrsConfig(prs_repository=PrsRepositoryType.API, repo_base_url=base_url, organisation_id="123456789"),
            brp=BrpConfig(mock_brp=True),
        )

    assert expected_error in str(e.value)


@pytest.mark.parametrize(
    "jwe_factory, jwe_encryption_key, should_raise_error",
    [
        (JweFactoryType.JOSE, None, True),
        (JweFactoryType.JOSE, "some_key", False),
        (JweFactoryType.NOOP, None, False),
        (JweFactoryType.NOOP, "some_key", False),
    ],
)
def test_app_config_jwe_encryption_key_validation(
    jwe_factory: JweFactoryType, jwe_encryption_key: str | None, should_raise_error: bool
) -> None:
    if should_raise_error:
        with pytest.raises(ValidationError) as exc_info:
            AppConfig(
                name="vad",
                loglevel=LogLevel.INFO,
                uvicorn_app=False,
                jwe_factory=jwe_factory,
                jwe_encryption_key=jwe_encryption_key,
            )
        assert "jwe_encryption_key is required when jwe_factory is 'jose'" in str(exc_info.value)
    else:
        config = AppConfig(
            name="vad",
            loglevel=LogLevel.INFO,
            uvicorn_app=False,
            jwe_factory=jwe_factory,
            jwe_encryption_key=jwe_encryption_key,
        )
        assert config.jwe_encryption_key == jwe_encryption_key
