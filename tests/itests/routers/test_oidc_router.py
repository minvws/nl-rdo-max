from unittest.mock import MagicMock

import pytest
from dependency_injector import containers, providers
from fastapi import Response, Request
from fastapi.datastructures import Headers

from app.dependency_injection.config import RouterConfig
from app.models.authorize_request import AuthorizeRequest
from app.models.token_request import TokenRequest

mocked_provider = MagicMock()


class OverridingContainer(containers.DeclarativeContainer):
    oidc_provider = providers.Object(mocked_provider)


@pytest.fixture
def oidc_provider_mocked(container_overrides):
    def override_oidc(container):
        overiding_container = OverridingContainer()
        container.services.override(overiding_container)

    container_overrides.append(override_oidc)


def test_well_known(lazy_app, oidc_provider_mocked):
    fake_response = Response("expected", status_code=234)
    mocked_provider.well_known.return_value = fake_response
    app = lazy_app.value
    actual_response = app.get("/.well-known/openid-configuration")
    assert actual_response.text == "expected"
    assert actual_response.status_code == 234

    mocked_provider.well_known.assert_called()


def test_authorize(lazy_app, oidc_provider_mocked):
    fake_response = Response("expected", status_code=234)
    authorize_request = AuthorizeRequest(
        client_id="ci",
        redirect_uri="ru",
        response_type="code",
        nonce="n",
        scope="s",
        state="s",
        code_challenge="cc",
        code_challenge_method="S256",
    )
    mocked_provider.present_login_options_or_authorize.return_value = fake_response
    app = lazy_app.value
    actual_response = app.get(
        "/authorize?client_id=ci&redirect_uri=ru&response_type=code&nonce=n&scope=s&state=s&code_challenge=cc&code_challenge_method=S256"
    )
    assert actual_response.text == "expected"
    assert actual_response.status_code == 234
    mocked_provider.present_login_options_or_authorize.assert_called_with(
        mocked_provider.present_login_options_or_authorize.call_args_list[0][0][0],
        authorize_request,
    )


def test_accesstoken(lazy_app, oidc_provider_mocked):
    fake_response = Response("expected", status_code=234)
    token_request = TokenRequest(
        grant_type="gt",
        code="c",
        redirect_uri="ru",
        code_verifier="cv",
        client_id="ci",
        query_string="grant_type=gt&code=c&redirect_uri=ru&code_verifier=cv&client_id=ci",
    )
    mocked_provider.token.return_value = fake_response
    app = lazy_app.value
    actual_response = app.post(
        "/token",
        headers={"a": "b"},
        data="grant_type=gt&code=c&redirect_uri=ru&code_verifier=cv&client_id=ci",
    )
    assert actual_response.text == "expected"
    assert actual_response.status_code == 234

    # Check if the headers are received correctly
    called_headers = mocked_provider.token.call_args[0][1]
    assert isinstance(called_headers, Headers)
    assert called_headers.get("a") == "b"
    assert called_headers.get("accept") == "*/*"

    mocked_provider.token.assert_called_with(token_request, called_headers)


def test_jwks(lazy_app, oidc_provider_mocked):
    fake_response = Response("expected", status_code=234)
    mocked_provider.jwks.return_value = fake_response
    app = lazy_app.value
    actual_response = app.get("/jwks")
    assert actual_response.text == "expected"
    assert actual_response.status_code == 234

    mocked_provider.jwks.assert_called()


def test_userinfo(lazy_app, oidc_provider_mocked):
    fake_response = Response("expected", status_code=234)
    mocked_provider.userinfo.return_value = fake_response
    app = lazy_app.value
    actual_response = app.get("/userinfo")
    assert actual_response.text == "expected"
    assert actual_response.status_code == 234

    mocked_provider.userinfo.assert_called()
    assert isinstance(mocked_provider.userinfo.call_args_list[0][0][0], Request)
