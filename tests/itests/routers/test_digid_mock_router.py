from unittest.mock import MagicMock

import pytest
from dependency_injector import containers, providers
from fastapi import Response, Request

from app.models.digid_mock_requests import DigiDMockRequest, DigiDMockCatchRequest

mocked_provider = MagicMock()


class OverridingContainer(containers.DeclarativeContainer):
    digid_mock_provider = providers.Object(mocked_provider)


@pytest.fixture
def digid_mock_provider_mocked(container_overrides):
    def override_digid(container):
        overiding_container = OverridingContainer()
        container.services.override(overiding_container)

    container_overrides.append(override_digid)


def test_digid_mock(lazy_app, digid_mock_provider_mocked):
    fake_response = Response("expected", status_code=234)
    digid_mock_request = DigiDMockRequest.from_request(
        SAMLRequest="a", RelayState="b", idp_name="c", state="d", authorize_request="e"
    )

    mocked_provider.digid_mock.return_value = fake_response

    app = lazy_app.value
    digid_post = app.post(
        "/digid-mock?idp_name=c&state=d&authorize_request=e",
        data={"SAMLRequest": "a", "RelayState": "b"},
    )
    assert digid_post.text == "expected"
    assert digid_post.status_code == 234
    request = mocked_provider.digid_mock.call_args_list[0][0][0]
    mocked_provider.digid_mock.assert_called_with(request, digid_mock_request)
    assert isinstance(request, Request)


def test_digid_mock_catch1(lazy_app, digid_mock_provider_mocked):
    fake_response = Response("expected", status_code=234)

    mocked_provider.digid_mock_catch.return_value = fake_response

    digid_mock_catch_request = DigiDMockCatchRequest(
        bsn="d", SAMLart="s", RelayState="r"
    )
    # digid_mock.login_digid.return_value = fake_response
    app = lazy_app.value
    digid_get = app.get(f"/digid-mock-catch?bsn=d&SAMLart=s&RelayState=r")
    assert digid_get.text == "expected"
    assert digid_get.status_code == 234

    mocked_provider.digid_mock_catch.assert_called_with(digid_mock_catch_request)
