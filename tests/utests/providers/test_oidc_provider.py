import time
from typing import List, Dict

from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes
from fastapi.exceptions import HTTPException
from configparser import ConfigParser
from jwcrypto.jwt import JWT

from app.constants import CLIENT_ASSERTION_TYPE
from app.exceptions.max_exceptions import (
    ServerErrorException,
    UnauthorizedError,
    InvalidRedirectUriException,
    InvalidClientException,
    InvalidResponseType,
)
from app.misc.utils import load_jwk
from app.models.authentication_meta import AuthenticationMeta
from app.models.authorize_request import AuthorizeRequest
from app.models.login_method import LoginMethod, LoginMethodWithLink
from app.models.login_method_type import LoginMethodType
from app.models.response_type import ResponseType
from app.providers.oidc_provider import OIDCProvider


def create_oidc_provider(
    pyop_provider=MagicMock(),
    authentication_cache=MagicMock(),
    rate_limiter=MagicMock(),
    clients=None,
    saml_response_factory=MagicMock(),
    response_factory=MagicMock(),
    userinfo_service=MagicMock(),
    app_mode="am",
    environment="test",
    login_methods=None,
    authentication_handler_factory=MagicMock(),
    external_base_url="external_base_url",
    external_http_requests_timeout_seconds=2,
    template_service=MagicMock(),
    wildcard_allowed=False,
    token_authentication_validator=MagicMock(),
):
    if login_methods is None:
        login_methods = [LoginMethod(name="login_option", type=LoginMethodType.OIDC)]

    return OIDCProvider(
        pyop_provider,
        authentication_cache,
        rate_limiter,
        clients if clients is not None else {},
        saml_response_factory,
        response_factory,
        userinfo_service,
        app_mode,
        environment,
        login_methods,
        authentication_handler_factory,
        external_base_url,
        external_http_requests_timeout_seconds,
        "sidebar.html",
        template_service,
        wildcard_allowed,
        token_authentication_validator,
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
    template_response = MagicMock()

    template_service = MagicMock()
    template_service.render_layout = MagicMock()
    template_service.render_layout.return_value = template_response

    client = {"name": "name"}
    oidc_provider = create_oidc_provider(
        clients={"client_id": client},
        login_methods=[
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ],
        external_base_url="http://base_url",
        template_service=template_service,
    )

    request = MagicMock()
    request.client_id = "client_id"
    request.url = (
        "http://localhost:8000/redirect_path?redirect_uri=redirect_uri&key=value"
    )

    login_methods = oidc_provider._get_login_methods({"name": "name"}, request)
    request.query_params = {"redirect_uri": "redirect_uri?key=value"}

    actual = oidc_provider._provide_login_options_response(
        "name", request, login_methods
    )

    template_service.render_layout.assert_called_with(
        request=request,
        template_name="login_options.html",
        page_title="name - Inlogmethode selecteren",
        page_context={
            "ura_name": "name",
            "login_methods": {
                "a": LoginMethodWithLink(
                    name="a",
                    logo=None,
                    text="",
                    type=LoginMethodType.SPECIFIC,
                    hidden=False,
                    url="http://base_url/redirect_path?redirect_uri=redirect_uri&key=value&login_hint=a",
                ),
                "b": LoginMethodWithLink(
                    name="b",
                    logo=None,
                    text="",
                    type=LoginMethodType.OIDC,
                    hidden=False,
                    url="http://base_url/redirect_path?redirect_uri=redirect_uri&key=value&login_hint=b",
                ),
            },
            "redirect_uri": "redirect_uri?key=value&error=login_required&error_description=Authentication+cancelled",
        },
        sidebar_template="sidebar.html",
    )
    assert actual == template_response


def test_provide_login_options_response_with_zero_login_options(mocker):
    templates_mock = MagicMock()
    templates_mock.templates.TemplateResponse = MagicMock()

    oidc_provider = create_oidc_provider(
        template_service=templates_mock,
    )
    request = MagicMock()
    authorize_request = MagicMock()
    login_methods = []

    authorize_request.client_id = "client_id"

    with pytest.raises(UnauthorizedError):
        oidc_provider._provide_login_options_response("name", request, login_methods)
    templates_mock.templates.TemplateResponse.assert_not_called()


def test_provide_login_options_response_with_one_login_options(mocker):
    templates_mock = MagicMock()
    templates_mock.templates.TemplateResponse = MagicMock()

    oidc_provider = create_oidc_provider()
    request = MagicMock()
    login_methods = [LoginMethod(name="a", type=LoginMethodType.SPECIFIC)]

    actual = oidc_provider._provide_login_options_response(
        "name", request, login_methods
    )

    templates_mock.templates.TemplateResponse.assert_not_called()
    assert actual is None


def test_get_login_methods():
    oidc_provider = create_oidc_provider(
        login_methods=[
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ],
        clients={"client_id": {"exclude_login_methods": []}},
    )
    authorize_request = MagicMock()
    authorize_request.login_hints = ["a", "b"]
    client = {"name": "name"}
    authorize_request.client_id = "client_id"
    actual = oidc_provider._get_login_methods(client, authorize_request)
    assert actual == [
        LoginMethod(name="a", type=LoginMethodType.SPECIFIC, hidden=False),
        LoginMethod(name="b", type=LoginMethodType.OIDC, hidden=False),
    ]


def test_get_login_methods_with_invalid_option_provided():
    oidc_provider = create_oidc_provider(
        login_methods=[
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ],
        clients={"client_id": {"exclude_login_methods": []}},
    )
    client = {"name": "name"}
    authorize_request = MagicMock()
    authorize_request.login_hints = ["a", "c"]
    authorize_request.client_id = "client_id"
    actual = oidc_provider._get_login_methods(client, authorize_request)
    assert actual == [
        LoginMethod(name="a", type=LoginMethodType.SPECIFIC, hidden=False)
    ]


def test_get_login_methods_with_none_provided():
    oidc_provider = create_oidc_provider(
        login_methods=[
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ],
        clients={"client_id": {"exclude_login_methods": []}},
    )
    client = {"name": "name"}
    authorize_request = MagicMock()
    authorize_request.login_hints = []
    authorize_request.client_id = "client_id"
    actual = oidc_provider._get_login_methods(client, authorize_request)
    assert actual == [
        LoginMethod(name="a", type=LoginMethodType.SPECIFIC, hidden=False),
        LoginMethod(name="b", type=LoginMethodType.OIDC, hidden=False),
    ]


def test_get_login_methods_with_one_provided():
    oidc_provider = create_oidc_provider(
        login_methods=[
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ],
        clients={"client_id": {"exclude_login_methods": []}},
    )
    client = {"name": "name"}
    authorize_request = MagicMock()
    authorize_request.login_hints = ["b"]
    authorize_request.client_id = "client_id"
    actual = oidc_provider._get_login_methods(client, authorize_request)
    assert actual == [LoginMethod(name="b", type=LoginMethodType.OIDC, hidden=False)]


def test_get_login_methods_with_excluded_provided_method():
    oidc_provider = create_oidc_provider(
        login_methods=[
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ],
        clients={"client_id": {"exclude_login_methods": ["b"]}},
    )
    client = {"exclude_login_methods": ["b"]}
    authorize_request = MagicMock()
    authorize_request.login_hints = ["b"]
    authorize_request.client_id = "client_id"
    actual = oidc_provider._get_login_methods(client, authorize_request)
    assert actual == [
        LoginMethod(name="a", type=LoginMethodType.SPECIFIC, hidden=False)
    ]


def test_get_login_methods_with_excluded_default_method():
    oidc_provider = create_oidc_provider(
        login_methods=[
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ],
        clients={"client_id": {"exclude_login_methods": ["a"]}},
    )
    client = {"exclude_login_methods": ["a"]}
    authorize_request = MagicMock()
    authorize_request.login_hints = []
    authorize_request.client_id = "client_id"
    actual = oidc_provider._get_login_methods(client, authorize_request)
    assert actual == [LoginMethod(name="b", type=LoginMethodType.OIDC, hidden=False)]


def test_get_login_methods_with_client_method():
    oidc_provider = create_oidc_provider(
        login_methods=[
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ],
        clients={"client_id": {"login_methods": ["b"]}},
    )
    client = {"login_methods": ["b"]}
    authorize_request = MagicMock()
    authorize_request.login_hints = []
    authorize_request.client_id = "client_id"
    actual = oidc_provider._get_login_methods(client, authorize_request)
    assert actual == [LoginMethod(name="b", type=LoginMethodType.OIDC, hidden=False)]


def test_present_login_options_or_authorize():
    oidc_provider = create_oidc_provider(clients={"client_id": {"name": "name"}})
    request = MagicMock()
    authorize_request = MagicMock()
    authorize_request.client_id = "client_id"
    ret_value = MagicMock()
    client = {"name": "name"}

    with patch.object(
        OIDCProvider, "_validate_authorize_request"
    ) as validate_authorize_request_method, patch.object(
        OIDCProvider, "_get_login_methods"
    ) as get_login_methods_method, patch.object(
        OIDCProvider, "_provide_login_options_response"
    ) as provide_login_options_response_method, patch.object(
        OIDCProvider, "_authorize"
    ) as authorize_method:
        login_methods = [
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
            LoginMethod(name="b", type=LoginMethodType.OIDC),
        ]
        get_login_methods_method.return_value = login_methods
        provide_login_options_response_method.return_value = None
        authorize_method.return_value = ret_value
        login_options_or_authorize = oidc_provider.present_login_options_or_authorize(
            request, authorize_request
        )

        validate_authorize_request_method.assert_called_with(authorize_request)
        get_login_methods_method.assert_called_with(client, authorize_request)
        provide_login_options_response_method.assert_called_with(
            "name", request, login_methods
        )
        authorize_method.assert_called_with(
            request,
            authorize_request,
            LoginMethod(name="a", type=LoginMethodType.SPECIFIC),
        )

        assert login_options_or_authorize == ret_value


def test_invalid_client_exception():
    oidc_provider = create_oidc_provider(clients={"client_id": {"name": "name"}})
    authorize_request = MagicMock()
    authorize_request.client_id = "other_client_id"

    with pytest.raises(InvalidClientException):
        oidc_provider._validate_authorize_request(authorize_request)


@pytest.mark.parametrize(
    "wildcard_allowed, environment, allowed_redirect_uri, test_redirect_uri, is_valid",
    [
        (False, "development", "https://redirect_uri", "https://redirect_uri", True),
        (False, "development", "http://redirect_uri", "http://redirect_uri", True),
        (False, "development", "https://redirect_uri", "http://redirect_uri", False),
        (
            False,
            "development",
            "https://redirect_uri",
            "https://redirect_uri?query=param",
            False,
        ),
        (
            False,
            "development",
            "https://redirect_uri?query=param",
            "https://redirect_uri?query=param",
            True,
        ),
        (True, "development", "*", "http://redirect_uri_example_a", True),
        (True, "development", "*", "https://redirect_uri_example_b", True),
        (False, "development", "*", "http://redirect_uri_example_a", False),
        (False, "development", "*", "https://redirect_uri_example_b", False),
        (True, "develop", "*", "http://redirect_uri_example_a", True),
        (True, "some-other-environment", "*", "http://redirect_uri_example_a", True),
        (False, "production", "https://redirect_uri", "https://redirect_uri", True),
        (False, "production", "http://redirect_uri", "http://redirect_uri", True),
        (False, "production", "https://redirect_uri", "http://redirect_uri", False),
        (True, "prod", "*", "http://redirect_uri_example_a", False),
        (True, "production", "*", "http://redirect_uri_example_a", False),
        (True, "production", "*", "https://redirect_uri_example_b", False),
        (False, "production", "*", "http://redirect_uri_example_a", False),
        (False, "production", "*", "https://redirect_uri_example_b", False),
    ],
)
def test_redirect_uris(
    wildcard_allowed, environment, allowed_redirect_uri, test_redirect_uri, is_valid
):
    oidc_provider = create_oidc_provider(
        environment=environment,
        wildcard_allowed=wildcard_allowed,
        clients={
            "client_id": {
                "name": "name",
                "redirect_uris": [allowed_redirect_uri],
                "response_types": [ResponseType.CODE],
            }
        },
    )

    authorize_request = MagicMock()
    authorize_request.client_id = "client_id"
    authorize_request.redirect_uri = test_redirect_uri
    authorize_request.response_type = ResponseType.CODE

    if not is_valid:
        with pytest.raises(InvalidRedirectUriException):
            oidc_provider._validate_authorize_request(authorize_request)

    else:
        oidc_provider._validate_authorize_request(authorize_request)


@pytest.mark.parametrize(
    "allowed_response_types, test_response_type, is_valid",
    [
        (["code"], "code", True),
        (["code"], "", False),
        (["code"], "something-different", False),
        ([], "", False),
    ],
)
def test_response_types(allowed_response_types, test_response_type, is_valid):
    oidc_provider = create_oidc_provider(
        clients={
            "client_id": {
                "name": "name",
                "redirect_uris": ["https://redirect_uri"],
                "response_types": allowed_response_types,
            }
        },
    )

    authorize_request = MagicMock()
    authorize_request.client_id = "client_id"
    authorize_request.redirect_uri = "https://redirect_uri"
    authorize_request.response_type = test_response_type

    if not is_valid:
        with pytest.raises(InvalidResponseType):
            oidc_provider._validate_authorize_request(authorize_request)

    else:
        oidc_provider._validate_authorize_request(authorize_request)


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

    login_option = LoginMethod(name="a", type=LoginMethodType.OIDC)

    authorize_request = AuthorizeRequest(
        client_id="str",
        redirect_uri="str",
        response_type=ResponseType.CODE,
        nonce="str",
        scope="str",
        state="str",
        code_challenge="str",
        code_challenge_method="S256",
        login_hint="a",
    )

    pyop_provider.parse_authentication_request.return_value = (
        pyop_authentication_request
    )

    authentication_cache.create_authentication_request_state.return_value = "rand"

    authentication_cache.create_randstate.return_value = "randstate"

    authorize_response.session_id = "session_id"
    authorize_response.response = "actual_response"

    request.client.host = "some.ip.address"
    request.headers = {"Authorization": "bearer some token"}

    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        rate_limiter=rate_limiter,
        authentication_cache=authentication_cache,
        authentication_handler_factory=authentication_handler_factory,
    )
    login_handler_response = oidc_provider._authorize(
        request, authorize_request, login_option
    )
    assert login_handler_response == "actual_response"

    rate_limiter.validate_outage.assert_called()

    pyop_provider.parse_authentication_request.assert_called_with(
        "client_id=str&redirect_uri=str&response_type=code&nonce=str&scope=str&state=str"
        + "&code_challenge=str&code_challenge_method=S256",
        request.headers,
    )

    rate_limiter.ip_limit_test.assert_called_with(request.client.host)

    authentication_handler_factory.create.assert_called_with(login_option)

    login_handler.authentication_state.assert_called_with(authorize_request)

    authentication_cache.create_randstate.assert_called_with(
        pyop_authentication_request, authorize_request
    )

    authentication_meta = AuthenticationMeta.create_authentication_meta(
        request, login_option
    )

    authentication_cache.cache_authentication_request_state.assert_called_with(
        pyop_authentication_request,
        authorize_request,
        "randstate",
        authentication_state,
        login_option.name,
        "session_id",
        authentication_meta=authentication_meta,
        req_acme_tokens=None,
    )

    login_handler.authorize_response.assert_called_with(
        request,
        authorize_request,
        pyop_authentication_request,
        authentication_state,
        "randstate",
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
        code_challenge_method="S256",
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
    )
    with pytest.raises(ServerErrorException):
        oidc_provider._authorize(
            request,
            authorize_request,
            LoginMethod(name="login_option", type=LoginMethodType.OIDC),
        )

    rate_limiter.validate_outage.assert_called()
    pyop_provider.parse_authentication_request.assert_called_with(
        "client_id=str&redirect_uri=str&response_type=code&nonce=str&scope=str&state=str"
        + "&code_challenge=str&code_challenge_method=S256",
        request.headers,
    )


def test_token_with_expired_authentication():
    authentication_cache = MagicMock()
    authentication_cache.get_acs_context.return_value = None
    token_request = MagicMock()
    token_request.client_id = "client_id"
    headers = MagicMock()
    token_request.code = "c"
    oidc_provider = create_oidc_provider(
        authentication_cache=authentication_cache,
        clients={"client_id": {"name": "name"}},
    )
    with pytest.raises(HTTPException):
        oidc_provider.token(token_request, headers)
    authentication_cache.get_acs_context.assert_called_with("c")


def test_token():
    pyop_provider = MagicMock()
    authentication_cache = MagicMock()
    userinfo_service = MagicMock()
    token_request = MagicMock()
    headers = MagicMock()
    acs_context = MagicMock()
    userinfo = MagicMock()
    token_response = MagicMock()
    token_request.code = "c"
    token_request.query_string = "qs"
    token_request.client_id = "client_id"
    authentication_cache.get_acs_context.return_value = acs_context
    pyop_provider.handle_token_request.return_value = token_response
    userinfo_service.request_userinfo_for_artifact.return_value = userinfo
    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        userinfo_service=userinfo_service,
        authentication_cache=authentication_cache,
        clients={"client_id": {"name": "name"}},
    )
    assert token_response == oidc_provider.token(token_request, headers)
    authentication_cache.get_acs_context.assert_called_with("c")
    pyop_provider.handle_token_request.assert_called_with("qs", headers)
    authentication_cache.cache_userinfo_context.assert_called_with(
        token_response["access_token"],
        token_response["access_token"],
        acs_context,
        client_content_type=None,
    )


def test_token_with_client_content_type():
    pyop_provider = MagicMock()
    authentication_cache = MagicMock()
    userinfo_service = MagicMock()
    token_request = MagicMock()
    headers = MagicMock()
    acs_context = MagicMock()
    userinfo = MagicMock()
    token_response = MagicMock()
    token_request.code = "c"
    token_request.query_string = "qs"
    token_request.client_id = "client_id"
    authentication_cache.get_acs_context.return_value = acs_context
    pyop_provider.handle_token_request.return_value = token_response
    userinfo_service.request_userinfo_for_artifact.return_value = userinfo
    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        userinfo_service=userinfo_service,
        authentication_cache=authentication_cache,
        clients={"client_id": {"name": "name", "content_type": "application/json"}},
    )
    assert token_response == oidc_provider.token(token_request, headers)
    authentication_cache.get_acs_context.assert_called_with("c")
    pyop_provider.handle_token_request.assert_called_with("qs", headers)
    authentication_cache.cache_userinfo_context.assert_called_with(
        token_response["access_token"],
        token_response["access_token"],
        acs_context,
        client_content_type="application/json",
    )


def test_token_with_client_authentication_method():
    config = ConfigParser()
    config.read("tests/max.test.conf")

    pyop_provider = MagicMock()
    authentication_cache = MagicMock()
    userinfo_service = MagicMock()
    acs_context = MagicMock()
    userinfo = MagicMock()
    token_response = MagicMock()
    token_authentication_validator = MagicMock()
    authentication_cache.get_acs_context.return_value = acs_context
    pyop_provider.handle_token_request.return_value = token_response
    userinfo_service.request_userinfo_for_artifact.return_value = userinfo
    clients = {
        "client_id": {
            "name": "name",
            "client_public_key_path": "secrets/clients/test_client/test_client.crt",
            "client_private_key_path": "secrets/clients/test_client/test_client.key",
            "client_authentication_method": "private_key_jwt",
        }
    }

    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        userinfo_service=userinfo_service,
        authentication_cache=authentication_cache,
        clients=clients,
        token_authentication_validator=token_authentication_validator,
    )

    client_id = "client_id"
    client = clients[client_id]
    client_private_key = load_jwk(client["client_private_key_path"])
    client_assertion_jwt = JWT(
        header={"alg": "RS256", "x5t": client_private_key.thumbprint(hashes.SHA256())},
        claims={
            "iss": "37692967-0a74-4e91-85ec-a4250e7ad5e8",
            "sub": "37692967-0a74-4e91-85ec-a4250e7ad5e8",
            "aud": "example.com",
            "exp": int(time.time()),
        },
    )
    client_assertion_jwt.make_signed_token(client_private_key)
    token_request = MagicMock()
    token_request.code = "c"
    token_request.query_string = "qs"
    token_request.client_id = client_id
    token_request.client_assertion = client_assertion_jwt.serialize()
    token_request.client_assertion_type = CLIENT_ASSERTION_TYPE
    headers = MagicMock()

    assert token_response == oidc_provider.token(token_request, headers)
    authentication_cache.get_acs_context.assert_called_with("c")
    pyop_provider.handle_token_request.assert_called_with("qs", headers)
    authentication_cache.cache_userinfo_context.assert_called_with(
        token_response["access_token"],
        token_response["access_token"],
        acs_context,
        client_content_type=None,
    )
    token_authentication_validator.validate_client_authentication.assert_called_with(
        client_id=token_request.client_id,
        client=client,
        client_assertion_jwt=token_request.client_assertion,
        client_assertion_type=token_request.client_assertion_type,
    )


def test_create_pyop_authentication_request():
    pyop_provider = MagicMock()
    request = MagicMock()
    authorize_request = AuthorizeRequest(
        client_id="client_id",
        redirect_uri="redirect_uri",
        response_type="response_type",
        nonce="nonce",
        scope="scope",
        state="state",
        code_challenge="code_challenge",
        code_challenge_method="S256",
        login_hint="bla",
        claims="bla",
    )
    oidc_provider = create_oidc_provider(pyop_provider=pyop_provider)

    pyop_provider.parse_authentication_request.return_value = "expected_return_value"

    actual = oidc_provider._create_pyop_authentication_request(
        request, authorize_request
    )

    assert actual == "expected_return_value"
    pyop_provider.parse_authentication_request.assert_called_with(
        "client_id=client_id&redirect_uri=redirect_uri&response_type=response_type&nonce=nonce&scope=scope&state=state&code_challenge=code_challenge&code_challenge_method=S256",
        request.headers,
    )
