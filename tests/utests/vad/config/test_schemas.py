import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture

from app.vad.config.schemas import (
    AppConfig,
    BrpConfig,
    Config,
    PrsConfig,
    PrsRepositoryType,
)
from app.vad.logging.schemas import LogLevel


def test_it_throws_no_error_on_valid_config() -> None:
    Config(
        app=AppConfig(
            name="VAD",
            loglevel=LogLevel.CRITICAL,
            uvicorn_app=False,
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
            app=AppConfig(
                name="VAD",
                loglevel=loglevel,
                uvicorn_app=False,
            ),
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
def test_it_requires_base_url_when_using_prs_api_repo(
    base_url: str, expected_error: str
) -> None:
    with pytest.raises(ValidationError) as e:
        Config(
            app=AppConfig(
                name="VAD",
                loglevel=LogLevel.CRITICAL,
                uvicorn_app=False,
            ),
            prs=PrsConfig(
                prs_repository=PrsRepositoryType.API,
                repo_base_url=base_url,
                organisation_id="123456789",
            ),
            brp=BrpConfig(mock_brp=True),
        )

    assert expected_error in str(e.value)
