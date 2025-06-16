from unittest.mock import MagicMock
from app.providers.eherkenning_mock_provider import EherkenningMockProvider
from app.models.eherkenning_mock_requests import (
    EherkenningMockRequest,
    EherkenningMockCatchRequest,
)


def test_eherkenning_mock(mocker):
    # Create a mock for Response
    response_mock = MagicMock()

    # Create a mock for JinjaTemplateService and its TemplateResponse method
    mock_jinja_service = MagicMock()
    mock_jinja_service.templates.TemplateResponse = MagicMock()
    mock_jinja_service.templates.TemplateResponse.return_value = response_mock

    # Instantiate EherkenningMockProvider with the mocked JinjaTemplateService
    provider = EherkenningMockProvider(mock_jinja_service)

    request_mock = MagicMock()

    eherkenning_mock_request = EherkenningMockRequest(
        state="s",
        SAMLRequest="sr",
        RelayState="rs",
        authorize_request="ar",
        idp_name="in",
    )
    mocker.patch("uuid.uuid4", return_value="1234")

    actual_response = provider.eherkenning_mock(request_mock, eherkenning_mock_request)

    assert actual_response == response_mock

    mock_jinja_service.templates.TemplateResponse.assert_called_with(
        request=request_mock,
        name="eherkenning_mock.html",
        context={
            "artifact": "1234",
            "relay_state": "rs",
            "state": "s",
            "idp_name": "in",
            "authorize_request": "ar",
        },
    )


def test_eherkenning_mock_catch():
    request = EherkenningMockCatchRequest(
        kvk="s",
        SAMLart="s",
        RelayState="ar",
    )

    mock_jinja_service = MagicMock()
    provider = EherkenningMockProvider(mock_jinja_service)

    actual_response = provider.eherkenning_mock_catch(request)

    assert actual_response.status_code == 303
    assert (
        actual_response.headers["location"] == "acs?SAMLart=s&RelayState=ar&mocking=1"
    )
