from unittest.mock import MagicMock

import pytest
from dependency_injector import containers, providers

digid_mock = MagicMock()


class OverridingContainer(containers.DeclarativeContainer):
    digid_mock_provider = providers.Object(digid_mock)


@pytest.fixture
def digid_mocked_router(container_overrides):
    def override_digid(container):
        overiding_container = OverridingContainer()
        container.services.override(overiding_container)

    container_overrides.append(override_digid)


def test_iets(lazy_app, digid_mocked_router):
    print("hier!")
