from unittest.mock import MagicMock, patch

import pytest
from fastapi.exceptions import HTTPException

from app.exceptions.max_exceptions import ServerErrorException
from app.models.authorize_request import AuthorizeRequest
from app.models.login_digid_request import LoginDigiDRequest
from app.models.response_type import ResponseType
from app.providers.oidc_provider import OIDCProvider


def create_oidc_provider(
    pyop_provider=MagicMock(),
    authentication_cache=MagicMock(),
    rate_limiter=MagicMock(),
    clients={},
    saml_identity_provider_service=MagicMock(),
    mock_digid=False,
    saml_response_factory=MagicMock(),
    artifact_resolving_service=MagicMock(),
    userinfo_service=MagicMock(),
    app_mode="am",
    environment="test",
):
    return OIDCProvider(
        pyop_provider,
        authentication_cache,
        rate_limiter,
        clients,
        saml_identity_provider_service,
        mock_digid,
        saml_response_factory,
        artifact_resolving_service,
        userinfo_service,
        app_mode,
        environment,
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


def test_authorize():
    pyop_provider = MagicMock()
    rate_limiter = MagicMock()
    saml_identity_provider_service = MagicMock()
    authentication_cache = MagicMock()
    saml_response_factory = MagicMock()
    identity_provider = MagicMock()
    saml_response = MagicMock()
    request = MagicMock()
    pyop_authentication_request = MagicMock()

    authorize_request = AuthorizeRequest(
        client_id="str",
        redirect_uri="str",
        response_type=ResponseType.CODE,
        nonce="str",
        scope="str",
        state="str",
        code_challenge="str",
        code_challenge_method="str",
    )

    login_digid_request = LoginDigiDRequest(
        state="rand", authorize_request=authorize_request, force_digid=False
    )

    pyop_provider.parse_authentication_request.return_value = (
        pyop_authentication_request
    )
    rate_limiter.get_identity_provider_name_and_validate_request.return_value = "idp"
    saml_identity_provider_service.get_identity_provider.return_value = (
        identity_provider
    )
    authentication_cache.create_authentication_request_state.return_value = "rand"
    saml_response_factory.create_saml_response.return_value = saml_response

    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        rate_limiter=rate_limiter,
        saml_identity_provider_service=saml_identity_provider_service,
        authentication_cache=authentication_cache,
        saml_response_factory=saml_response_factory,
    )

    with patch.object(
        OIDCProvider, "_validate_authorize_request"
    ) as validate_authorize_request:
        actual_saml_response = oidc_provider.authorize(authorize_request, request)
        assert actual_saml_response == saml_response

        validate_authorize_request.assert_called()
        rate_limiter.validate_outage.assert_called()
        pyop_provider.parse_authentication_request.assert_called_with(
            "client_id=str&redirect_uri=str&response_type=code&nonce=str&scope=str&state=str"
            + "&code_challenge=str&code_challenge_method=str",
            request.headers,
        )
        rate_limiter.get_identity_provider_name_and_validate_request.assert_called_with(
            request.client.host
        )
        saml_identity_provider_service.get_identity_provider.assert_called_with("idp")
        authentication_cache.create_authentication_request_state.assert_called_with(
            pyop_authentication_request, authorize_request, "idp"
        )

        saml_response_factory.create_saml_response.assert_called_with(
            False, identity_provider, login_digid_request, "rand"
        )


def test_authorize_with_mock_enabled():
    pyop_provider = MagicMock()
    rate_limiter = MagicMock()
    saml_identity_provider_service = MagicMock()
    authentication_cache = MagicMock()
    saml_response_factory = MagicMock()
    identity_provider = MagicMock()
    saml_response = MagicMock()
    request = MagicMock()
    pyop_authentication_request = MagicMock()

    authorize_request = AuthorizeRequest(
        client_id="str",
        redirect_uri="str",
        response_type=ResponseType.CODE,
        nonce="str",
        scope="str",
        state="str",
        code_challenge="str",
        code_challenge_method="str",
    )

    login_digid_request = LoginDigiDRequest(
        state="rand", authorize_request=authorize_request, force_digid=False
    )

    pyop_provider.parse_authentication_request.return_value = (
        pyop_authentication_request
    )
    rate_limiter.get_identity_provider_name_and_validate_request.return_value = "idp"
    saml_identity_provider_service.get_identity_provider.return_value = (
        identity_provider
    )
    authentication_cache.create_authentication_request_state.return_value = "rand"
    saml_response_factory.create_saml_response.return_value = saml_response

    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        rate_limiter=rate_limiter,
        saml_identity_provider_service=saml_identity_provider_service,
        authentication_cache=authentication_cache,
        saml_response_factory=saml_response_factory,
        mock_digid=True,
    )

    with patch.object(
        OIDCProvider, "_validate_authorize_request"
    ) as validate_authorize_request:
        actual_saml_response = oidc_provider.authorize(authorize_request, request)
        assert actual_saml_response == saml_response

        validate_authorize_request.assert_called()
        rate_limiter.validate_outage.assert_called()
        pyop_provider.parse_authentication_request.assert_called_with(
            "client_id=str&redirect_uri=str&response_type=code&nonce=str&scope=str&state=str"
            + "&code_challenge=str&code_challenge_method=str",
            request.headers,
        )
        rate_limiter.get_identity_provider_name_and_validate_request.assert_called_with(
            request.client.host
        )
        saml_identity_provider_service.get_identity_provider.assert_called_with("idp")
        authentication_cache.create_authentication_request_state.assert_called_with(
            pyop_authentication_request, authorize_request, "idp"
        )

        saml_response_factory.create_saml_response.assert_called_with(
            True, identity_provider, login_digid_request, "rand"
        )


def test_authorize_without_client():
    pyop_provider = MagicMock()
    rate_limiter = MagicMock()
    saml_identity_provider_service = MagicMock()
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
    )

    pyop_provider.parse_authentication_request.return_value = (
        pyop_authentication_request
    )

    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        rate_limiter=rate_limiter,
        saml_identity_provider_service=saml_identity_provider_service,
        authentication_cache=authentication_cache,
        saml_response_factory=saml_response_factory,
        mock_digid=True,
    )

    with patch.object(
        OIDCProvider, "_validate_authorize_request"
    ) as validate_authorize_request:
        with pytest.raises(ServerErrorException):
            oidc_provider.authorize(authorize_request, request)

        validate_authorize_request.assert_called()
        rate_limiter.validate_outage.assert_called()
        pyop_provider.parse_authentication_request.assert_called_with(
            "client_id=str&redirect_uri=str&response_type=code&nonce=str&scope=str&state=str"
            + "&code_challenge=str&code_challenge_method=str",
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
    resolved_artifact = MagicMock()
    userinfo = MagicMock()
    token_response = MagicMock()
    token_request.code = "c"
    token_request.query_string = "qs"
    authentication_cache.get_acs_context.return_value = acs_context
    pyop_provider.handle_token_request.return_value = token_response
    artifact_resolving_service.resolve_artifact.return_value = resolved_artifact
    userinfo_service.request_userinfo_for_artifact.return_value = userinfo
    oidc_provider = create_oidc_provider(
        pyop_provider=pyop_provider,
        artifact_resolving_service=artifact_resolving_service,
        userinfo_service=userinfo_service,
        authentication_cache=authentication_cache,
    )
    assert token_response == oidc_provider.token(token_request, headers)
    authentication_cache.get_acs_context.assert_called_with("c")
    pyop_provider.handle_token_request.assert_called_with("qs", headers)
    artifact_resolving_service.resolve_artifact.assert_called_with(acs_context)
    userinfo_service.request_userinfo_for_artifact.assert_called_with(
        acs_context, resolved_artifact
    )
    authentication_cache.cache_authentication_context.assert_called_with(
        token_response, userinfo
    )
