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

# pylint: disable=unused-argument
def test_get_bsn_from_artresponse(digid_config):
    art_resp_sector = 's00000000:900029365'
    assert get_provider()._get_bsn_from_art_resp(art_resp_sector) == '900029365' # pylint: disable=protected-access
