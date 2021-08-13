from inge6.models import SorryPageRequest
from inge6.provider import get_provider


def test_sorry_too_busy():
    request = SorryPageRequest(
        state = "state",
        redirect_uri = "uri",
        client_id = "test_client"
    )


    response = get_provider().sorry_too_busy(request)
    assert "Het is erg druk op dit moment, iets te druk zelfs." in response.body.decode()
