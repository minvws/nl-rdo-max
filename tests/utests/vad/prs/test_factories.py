import pytest
from fastapi.testclient import TestClient
from pytest_mock import MockerFixture

from app.vad.config.schemas import PrsConfig, PrsRepositoryType
from app.vad.prs.factories import PrsRepositoryFactory
from app.vad.prs.repositories import ApiPrsRepository, MockPrsRepository
from tests.utests.vad.utils import configure_bindings


@pytest.fixture
def mock_prs_config() -> PrsConfig:
    return PrsConfig(
        prs_repository=PrsRepositoryType.MOCK, repo_base_url="", organisation_id=""
    )


@pytest.fixture
def api_prs_config() -> PrsConfig:
    return PrsConfig(
        prs_repository=PrsRepositoryType.API,
        repo_base_url="http://localhost",
        organisation_id="test-org-id",
    )


@pytest.fixture
def invalid_prs_config(mocker: MockerFixture) -> PrsConfig:
    config_mock: PrsConfig = mocker.Mock(spec=PrsConfig)
    config_mock.prs_repository = "invalid"  # type: ignore
    config_mock.prs_repository = "test-org-id"  # type: ignore
    return config_mock


class TestPrsRepositoryFactory:
    def test_create_mock_repository(self, mock_prs_config: PrsConfig) -> None:
        factory = PrsRepositoryFactory(mock_prs_config)
        repository = factory.create()
        assert isinstance(repository, MockPrsRepository)

    # Using configure_bindings() here to use DI for the AsyncClient
    def test_create_api_repository(self, api_prs_config: PrsConfig) -> None:
        configure_bindings()

        factory = PrsRepositoryFactory(api_prs_config)
        repository = factory.create()

        assert isinstance(repository, ApiPrsRepository)
        assert repository._repo_base_url == "http://localhost"

    def test_factory_raises_error_with_invalid_config(
        self, invalid_prs_config: PrsConfig
    ) -> None:
        factory = PrsRepositoryFactory(invalid_prs_config)
        with pytest.raises(NotImplementedError):
            factory.create()
