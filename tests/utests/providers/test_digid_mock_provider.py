from unittest.mock import MagicMock

from app.providers.digid_mock_provider import DigidMockProvider


def test_login_digid():
    saml_response_factory = MagicMock()
    saml_identity_provider_service = MagicMock()
    authentication_cache = MagicMock()
    identity_provider = MagicMock()
    response_mock = MagicMock()
    login_digid_request = MagicMock()

    authentication_cache.get_authentication_request_state.return_value = {
        "id_provider": "ip"
    }
    saml_identity_provider_service.get_identity_provider.return_value = (
        identity_provider
    )
    saml_response_factory.create_saml_response.return_value = response_mock
    login_digid_request.state = "s"
    login_digid_request.force_digid = True

    provider_to_test = DigidMockProvider(
        saml_response_factory,
        saml_identity_provider_service,
        authentication_cache,
        "prod",
    )
    actual_response = provider_to_test.login_digid(login_digid_request)

    authentication_cache.get_authentication_request_state.assert_called_with("s")
    saml_identity_provider_service.get_identity_provider.assert_called_with("ip")
    saml_response_factory.create_saml_response.assert_called_with(
        mock_digid=False,
        saml_identity_provider=identity_provider,
        login_digid_request=login_digid_request,
        randstate=login_digid_request.state,
    )
    assert actual_response == response_mock


def test_login_digid_mock_disabled_when_environment_starts_with_prod():
    saml_response_factory = MagicMock()
    saml_identity_provider_service = MagicMock()
    authentication_cache = MagicMock()
    identity_provider = MagicMock()
    response_mock = MagicMock()
    login_digid_request = MagicMock()

    authentication_cache.get_authentication_request_state.return_value = {
        "id_provider": "ip"
    }
    saml_identity_provider_service.get_identity_provider.return_value = (
        identity_provider
    )
    saml_response_factory.create_saml_response.return_value = response_mock
    login_digid_request.state = "s"
    login_digid_request.force_digid = False

    provider_to_test = DigidMockProvider(
        saml_response_factory,
        saml_identity_provider_service,
        authentication_cache,
        "prodish",
    )
    actual_response = provider_to_test.login_digid(login_digid_request)

    authentication_cache.get_authentication_request_state.assert_called_with("s")
    saml_identity_provider_service.get_identity_provider.assert_called_with("ip")
    saml_response_factory.create_saml_response.assert_called_with(
        mock_digid=False,
        saml_identity_provider=identity_provider,
        login_digid_request=login_digid_request,
        randstate=login_digid_request.state,
    )
    assert actual_response == response_mock


def test_login_digid_mock_disabled_when_environment_starts_with_test():
    saml_response_factory = MagicMock()
    saml_identity_provider_service = MagicMock()
    authentication_cache = MagicMock()
    identity_provider = MagicMock()
    response_mock = MagicMock()
    login_digid_request = MagicMock()

    authentication_cache.get_authentication_request_state.return_value = {
        "id_provider": "ip"
    }
    saml_identity_provider_service.get_identity_provider.return_value = (
        identity_provider
    )
    saml_response_factory.create_saml_response.return_value = response_mock
    login_digid_request.state = "s"
    login_digid_request.force_digid = False

    provider_to_test = DigidMockProvider(
        saml_response_factory,
        saml_identity_provider_service,
        authentication_cache,
        "test",
    )
    actual_response = provider_to_test.login_digid(login_digid_request)

    authentication_cache.get_authentication_request_state.assert_called_with("s")
    saml_identity_provider_service.get_identity_provider.assert_called_with("ip")
    saml_response_factory.create_saml_response.assert_called_with(
        mock_digid=True,
        saml_identity_provider=identity_provider,
        login_digid_request=login_digid_request,
        randstate=login_digid_request.state,
    )
    assert actual_response == response_mock


def test_digid_mock(mocker):
    response_mock = MagicMock()
    request_mock = MagicMock()
    template_mock = mocker.patch("app.providers.digid_mock_provider.templates")
    template_mock.TemplateResponse.return_value = response_mock

    digid_mock_request = MagicMock()
    digid_mock_request.state = "s"
    digid_mock_request.authorize_request = "ar"
    digid_mock_request.idp_name = "in"
    digid_mock_request.RelayState = "rs"
    mocker.patch("uuid.uuid4", return_value="1234")

    actual_response = DigidMockProvider.digid_mock(request_mock, digid_mock_request)

    assert actual_response == response_mock

    template_mock.TemplateResponse.assert_called_with(
        "digid_mock.html",
        {
            "request": request_mock,
            "artifact": "1234",
            "relay_state": "rs",
            "state": "s",
            "idp_name": "in",
            "authorize_request": "ar",
        },
    )


def test_digid_mock_catch():
    digid_mock_catch_request = MagicMock()
    digid_mock_catch_request.bsn = "s"
    digid_mock_catch_request.RelayState = "ar"

    actual_response = DigidMockProvider.digid_mock_catch(digid_mock_catch_request)

    assert actual_response.status_code == 303
    assert (
        actual_response.headers["location"] == "/acs?SAMLart=s&RelayState=ar&mocking=1"
    )
