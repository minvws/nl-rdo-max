from unittest.mock import MagicMock

from app.providers.digid_mock_provider import DigidMockProvider


def test_digid_mock(mocker):
    # Create a mock for Response
    response_mock = MagicMock()

    # Create a mock for JinjaTemplateService and its TemplateResponse method
    mock_jinja_service = MagicMock()
    mock_jinja_service.templates.TemplateResponse = MagicMock()
    mock_jinja_service.templates.TemplateResponse.return_value = response_mock

    # Instantiate DigidMockProvider with the mocked JinjaTemplateService
    provider = DigidMockProvider(mock_jinja_service)

    request_mock = MagicMock()

    digid_mock_request = MagicMock()
    digid_mock_request.state = "s"
    digid_mock_request.authorize_request = "ar"
    digid_mock_request.idp_name = "in"
    digid_mock_request.RelayState = "rs"
    mocker.patch("uuid.uuid4", return_value="1234")

    actual_response = provider.digid_mock(request_mock, digid_mock_request)

    assert actual_response == response_mock

    mock_jinja_service.templates.TemplateResponse.assert_called_with(
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

    mock_jinja_service = MagicMock()
    provider = DigidMockProvider(mock_jinja_service)

    actual_response = provider.digid_mock_catch(digid_mock_catch_request)

    assert actual_response.status_code == 303
    assert (
        actual_response.headers["location"] == "acs?SAMLart=s&RelayState=ar&mocking=1"
    )
