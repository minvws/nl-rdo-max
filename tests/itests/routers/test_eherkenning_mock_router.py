from unittest.mock import MagicMock

import pytest
from dependency_injector import containers, providers
from fastapi import Response, Request

from app.models.eherkenning_mock_requests import (
    EherkenningMockRequest,
    EherkenningMockCatchRequest,
)

mocked_provider = MagicMock()


class OverridingContainer(containers.DeclarativeContainer):
    eherkenning_mock_provider = providers.Object(mocked_provider)


@pytest.fixture
def eherkenning_mock_provider_mocked(container_overrides):
    def override_eherkenning(container):
        overiding_container = OverridingContainer()
        container.services.override(overiding_container)

    container_overrides.append(override_eherkenning)


def test_eherkenning_mock(lazy_app, eherkenning_mock_provider_mocked):
    fake_response = Response("expected", status_code=234)
    eherkenning_mock_request = EherkenningMockRequest.from_request(
        SAMLRequest="a", RelayState="b", idp_name="c", state="d", authorize_request="e"
    )

    mocked_provider.eherkenning_mock.return_value = fake_response

    app = lazy_app.value
    eherkenning_post = app.post(
        "/eherkenning-mock?idp_name=c&state=d&authorize_request=e",
        data={"SAMLRequest": "a", "RelayState": "b"},
    )
    assert eherkenning_post.text == "expected"
    assert eherkenning_post.status_code == 234
    request = mocked_provider.eherkenning_mock.call_args_list[0][0][0]
    mocked_provider.eherkenning_mock.assert_called_with(
        request, eherkenning_mock_request
    )
    assert isinstance(request, Request)


def test_eherkenning_mock_catch(lazy_app, eherkenning_mock_provider_mocked):
    fake_response = Response("expected", status_code=234)

    mocked_provider.eherkenning_mock_catch.return_value = fake_response

    eherkenning_mock_catch_request = EherkenningMockCatchRequest(
        kvk="d", SAMLart="s", RelayState="r"
    )
    app = lazy_app.value
    eherkenning_get = app.get("/eherkenning-mock-catch?kvk=d&SAMLart=s&RelayState=r")
    assert eherkenning_get.text == "expected"
    assert eherkenning_get.status_code == 234

    mocked_provider.eherkenning_mock_catch.assert_called_with(
        eherkenning_mock_catch_request
    )
