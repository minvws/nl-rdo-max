from typing import List

from unittest.mock import MagicMock, patch

import pytest
from fastapi.exceptions import HTTPException

from app.exceptions.max_exceptions import ServerErrorException, UnauthorizedError
from app.models.authorize_request import AuthorizeRequest
from app.models.login_digid_request import LoginDigiDRequest
from app.models.response_type import ResponseType
from app.providers.oidc_provider import OIDCProvider


def create_oidc_provider(
    pyop_provider=MagicMock(),
    authentication_cache=MagicMock(),
    rate_limiter=MagicMock(),
    clients=None,
    mock_digid=False,
    saml_response_factory=MagicMock(),
    response_factory=MagicMock(),
    userinfo_service=MagicMock(),
    app_mode="am",
    environment="test",
    login_methods: List[str] = "login_method",
    authentication_handler_factory=MagicMock(),
    external_base_url="external_base_url",
):
    return OIDCProvider(
        pyop_provider,
        authentication_cache,
        rate_limiter,
        clients if clients is not None else {},
        mock_digid,
        saml_response_factory,
        response_factory,
        userinfo_service,
        app_mode,
        environment,
        login_methods,
        authentication_handler_factory,
        external_base_url,
    )


def test_well_known():
    pyop_provider = MagicMock()
    pyop_provider.provider_configuration.to_dict.return_value = {"key": "value"}
    actual = create_oidc_provider(pyop_provider=pyop_provider).well_known()
    assert actual.media_type == "application/json"
    assert actual.status_code == 200
    assert actual.body == b'{"key":"value"}'


def test_jwks():
    pyop_provider = MagicMock()
    pyop_provider.jwks = {"key": "value"}
    actual = create_oidc_provider(pyop_provider=pyop_provider).jwks()
    assert actual.media_type == "application/json"
    assert actual.status_code == 200
    assert actual.body == b'{"key":"value"}'


def test_provide_login_options_response_with_multiple_login_options(mocker):
    oidc_provider = create_oidc_provider(
        clients={"client_id": {"name": "name"}}, external_base_url="base_url"
    )
    request = MagicMock()
    authorize_request = MagicMock()
    template_response = MagicMock()
    redirect_url = MagicMock()
    login_methods = ["a", "b"]

    request.url.remove_query_params.return_value = redirect_url
    redirect_url.path = "/redirect_path"
    redirect_url.query = "query"
    authorize_request.client_id = "client_id"

    templates_mock = mocker.patch("app.providers.oidc_provider.templates")
    templates_mock.TemplateResponse.return_value = template_response

    actual = oidc_provider._provide_login_options_response(
        request, authorize_request, login_methods
    )

    request.url.remove_query_params.assert_called_with("login_hints")
    templates_mock.TemplateResponse.assert_called_with(
        "login_options.html",
        {
            "request": request,
            "login_methods": ["a", "b"],
            "ura_name": "name",
            "redirect_uri": "base_url/redirect_path?query",
        },
    )
    assert actual == template_response


def test_provide_login_options_response_with_zero_login_options(mocker):
    oidc_provider = create_oidc_provider()
    request = MagicMock()
    authorize_request = MagicMock()
    login_methods = []

    authorize_request.client_id = "client_id"

    templates_mock = mocker.patch("app.providers.oidc_provider.templates")

    with pytest.raises(UnauthorizedError):
        oidc_provider._provide_login_options_response(
            request, authorize_request, login_methods
        )
    templates_mock.TemplateResponse.assert_not_called()


def test_provide_login_options_response_with_one_login_options(mocker):
    oidc_provider = create_oidc_provider()
    request = MagicMock()
    authorize_request = MagicMock()
    login_methods = ["a"]
    templates_mock = mocker.patch("app.providers.oidc_provider.templates")

    actual = oidc_provider._provide_login_options_response(
        request, authorize_request, login_methods
    )

    templates_mock.TemplateResponse.assert_not_called()
    assert actual is None


def test_get_login_methods():
    oidc_provider = create_oidc_provider(login_methods=["a", "b"])
    authorize_request = MagicMock()
    authorize_request.login_hints = ["a", "b"]
    actual = oidc_provider._get_login_methods(authorize_request)
    assert actual == ["a", "b"]


def test_get_login_methods_with_invalid_option_provided():
    oidc_provider = create_oidc_provider(login_methods=["a", "b"])
    authorize_request = MagicMock()
    authorize_request.login_hints = ["a", "c"]
    actual = oidc_provider._get_login_methods(authorize_request)
    assert actual == ["a"]


def test_get_login_methods_with_none_provided():
    oidc_provider = create_oidc_provider(login_methods=["a", "b"])
    authorize_request = MagicMock()
    authorize_request.login_hints = []
    actual = oidc_provider._get_login_methods(authorize_request)
    assert actual == ["a", "b"]


def test_get_login_methods_with_one_provided():
    oidc_provider = create_oidc_provider(login_methods=["a", "b"])
    authorize_request = MagicMock()
    authorize_request.login_hints = ["b"]
    actual = oidc_provider._get_login_methods(authorize_request)
    assert actual == ["b"]


def test_present_login_options_or_authorize():
    oidc_provider = create_oidc_provider()
    request = MagicMock()
    authorize_request = MagicMock()
    ret_value = MagicMock()

    with patch.object(
        OIDCProvider, "_validate_authorize_request"
    ) as validate_authorize_request_method, patch.object(
        OIDCProvider, "_get_login_methods"
    ) as get_login_methods_method, patch.object(
        OIDCProvider, "_provide_login_options_response"
    ) as provide_login_options_response_method, patch.object(
        OIDCProvider, "_authorize"
    ) as authorize_method:
        get_login_methods_method.return_value = ["login_method"]
        provide_login_options_response_method.return_value = None
        authorize_method.return_value = ret_value
        login_options_or_authorize = oidc_provider.present_login_options_or_authorize(
            request, authorize_request
        )

        validate_authorize_request_method.assert_called_with(authorize_request)
        get_login_methods_method.assert_called_with(authorize_request)
        provide_login_options_response_method.assert_called_with(
            request, authorize_request, ["login_method"]
        )
        authorize_method.assert_called_with(request, authorize_request, "login_method")

        assert login_options_or_authorize == ret_value


def test_authorize():
    pyop_provider = MagicMock()
    rate_limiter = MagicMock()
    authentication_cache = MagicMock()
    request = MagicMock()
    pyop_authentication_request = MagicMock()
    authentication_handler_factory = MagicMock()
    login_handler = MagicMock()
    authorize_response = MagicMock()
    authentication_state = MagicMock()
    authentication_handler_factory.create.return_value = login_handler
    login_handler.authorize_response.return_value = authorize_response
    login_handler.authentication_state.return_value = authentication_state

    authorize_request = AuthorizeRequest(
        client_id="str",
        redirect_uri="str",
        response_type=ResponseType.CODE,
        nonce="str",
        scope="str",
        state="str",
        code_challenge="str",
        code_challenge_method="str",
        login_hint="a",
    )

    pyop_provider.parse_authentication_request.return_value = (
        pyop_authentication_request
    )

    authentication_cache.create_authentication_request_state.return_value = "rand"

    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        rate_limiter=rate_limiter,
        authentication_cache=authentication_cache,
        mock_digid=True,
        authentication_handler_factory=authentication_handler_factory,
    )
    login_handler_response = oidc_provider._authorize(
        request, authorize_request, "login_hint"
    )
    assert login_handler_response == authorize_response

    rate_limiter.validate_outage.assert_called()

    pyop_provider.parse_authentication_request.assert_called_with(
        "client_id=str&redirect_uri=str&response_type=code&nonce=str&scope=str&state=str"
        + "&code_challenge=str&code_challenge_method=str&login_hint=a",
        request.headers,
    )

    rate_limiter.ip_limit_test.assert_called_with(request.client.host)

    authentication_handler_factory.create.assert_called_with("login_hint")

    login_handler.authentication_state.assert_called_with(authorize_request)

    authentication_cache.create_authentication_request_state.assert_called_with(
        pyop_authentication_request,
        authorize_request,
        authentication_state,
        "login_hint",
    )

    login_handler.authorize_response.assert_called_with(
        request,
        authorize_request,
        pyop_authentication_request,
        authentication_state,
        "rand",
    )


def test_authorize_without_client():
    pyop_provider = MagicMock()
    rate_limiter = MagicMock()
    authentication_cache = MagicMock()
    saml_response_factory = MagicMock()
    request = MagicMock()
    pyop_authentication_request = MagicMock()

    request.client = None

    authorize_request = AuthorizeRequest(
        client_id="str",
        redirect_uri="str",
        response_type=ResponseType.CODE,
        nonce="str",
        scope="str",
        state="str",
        code_challenge="str",
        code_challenge_method="str",
        login_hint="a,b",
    )

    pyop_provider.parse_authentication_request.return_value = (
        pyop_authentication_request
    )

    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        rate_limiter=rate_limiter,
        authentication_cache=authentication_cache,
        saml_response_factory=saml_response_factory,
        mock_digid=True,
    )
    with pytest.raises(ServerErrorException):
        oidc_provider._authorize(request, authorize_request, "login_option")

    rate_limiter.validate_outage.assert_called()
    pyop_provider.parse_authentication_request.assert_called_with(
        "client_id=str&redirect_uri=str&response_type=code&nonce=str&scope=str&state=str"
        + "&code_challenge=str&code_challenge_method=str&login_hint=a%2Cb",
        request.headers,
    )


def test_token_with_expired_authentication():
    authentication_cache = MagicMock()
    authentication_cache.get_acs_context.return_value = None
    token_request = MagicMock()
    headers = MagicMock()
    token_request.code = "c"
    oidc_provider = create_oidc_provider(authentication_cache=authentication_cache)
    with pytest.raises(HTTPException):
        oidc_provider.token(token_request, headers)
    authentication_cache.get_acs_context.assert_called_with("c")


def test_token():
    pyop_provider = MagicMock()
    authentication_cache = MagicMock()
    artifact_resolving_service = MagicMock()
    userinfo_service = MagicMock()
    token_request = MagicMock()
    headers = MagicMock()
    acs_context = MagicMock()
    userinfo = MagicMock()
    token_response = MagicMock()
    token_request.code = "c"
    token_request.query_string = "qs"
    authentication_cache.get_acs_context.return_value = acs_context
    pyop_provider.handle_token_request.return_value = token_response
    userinfo_service.request_userinfo_for_artifact.return_value = userinfo
    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        userinfo_service=userinfo_service,
        authentication_cache=authentication_cache,
    )
    assert token_response == oidc_provider.token(token_request, headers)
    authentication_cache.get_acs_context.assert_called_with("c")
    pyop_provider.handle_token_request.assert_called_with("qs", headers)
    authentication_cache.cache_userinfo_context.assert_called_with(
        token_response["access_token"], token_response["access_token"], acs_context
    )
