from unittest.mock import MagicMock

import pytest
from dependency_injector import containers, providers
from fastapi import Response

from app.models.saml.assertion_consumer_service_request import (
    AssertionConsumerServiceRequest,
)

mocked_provider = MagicMock()


class OverridingContainer(containers.DeclarativeContainer):
    saml_provider = providers.Object(mocked_provider)


@pytest.fixture
def saml_provider_mocked(container_overrides):
    def override_saml(container):
        overiding_container = OverridingContainer()
        container.services.override(overiding_container)

    container_overrides.append(override_saml)


def test_assertion_consumer_service(lazy_app, saml_provider_mocked):
    fake_response = Response("expected", status_code=234)
    request = AssertionConsumerServiceRequest(SAMLart="s", RelayState="r", mocking=True)
    mocked_provider.handle_assertion_consumer_service.return_value = fake_response
    app = lazy_app.value
    actual = app.get("/acs?SAMLart=s&RelayState=r&mocking=1")
    assert actual.text == "expected"
    assert actual.status_code == 234

    mocked_provider.handle_assertion_consumer_service.assert_called_with(request)


def test_assertion_consumer_service_without_mocking(lazy_app, saml_provider_mocked):
    fake_response = Response("expected", status_code=234)
    request = AssertionConsumerServiceRequest(
        SAMLart="s", RelayState="r", mocking=False
    )
    mocked_provider.handle_assertion_consumer_service.return_value = fake_response
    app = lazy_app.value
    actual = app.get("/acs?SAMLart=s&RelayState=r")
    assert actual.text == "expected"
    assert actual.status_code == 234

    mocked_provider.handle_assertion_consumer_service.assert_called_with(request)


def test_metadata(lazy_app, saml_provider_mocked):
    fake_response = Response("expected", status_code=234)
    mocked_provider.metadata.return_value = fake_response
    app = lazy_app.value
    actual_response = app.get("/metadata/id_provider")
    assert actual_response.text == "expected"
    assert actual_response.status_code == 234

    mocked_provider.metadata.assert_called_with("id_provider")
