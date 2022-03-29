import json
import urllib
import jwt

from fastapi.testclient import TestClient

from inge6.main import app
from inge6.provider import Provider

from ..test_utils import get_settings

# pylint: disable=unused-argument
def test_consume_bsn_and_accesstoken(
    redis_mock, tvs_config, default_authorize_request_dict, mocker, mock_clients_db
):
    mock_provider = Provider(settings=get_settings(), redis_client=redis_mock)
    mock_provider.clients = mock_clients_db
    mocker.patch("inge6.main.PROVIDER", mock_provider)

    client = TestClient(app)
    bsn = "999991772"
    redirect_uri = "http://localhost:3000/login"
    client_id = "test_client"

    authorize_params = default_authorize_request_dict
    authorize_params["client_id"] = client_id
    authorize_params["redirect_uri"] = redirect_uri

    query_params: str = urllib.parse.urlencode(authorize_params)
    resp = client.get(f"/consume_bsn/{bsn}?{query_params}")
    assert resp.status_code == 200

    code = json.loads(resp.text)["code"][0]
    code_verifier = "SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c"

    acc_req_body = f"client_id={client_id}&redirect_uri={redirect_uri}&code={code}&code_verifier={code_verifier}&grant_type=authorization_code"

    accesstoken_resp = client.post("/accesstoken", acc_req_body)
    assert accesstoken_resp.status_code == 200

    accesstoken = json.loads(accesstoken_resp.content.decode())
    assert accesstoken["expires_in"] == 3600
    assert accesstoken["token_type"] == "Bearer"
    assert "access_token" in accesstoken

    id_token = jwt.decode(accesstoken["id_token"], options={"verify_signature": False})
    assert id_token["iss"] == get_settings().issuer
    assert id_token["nonce"] == authorize_params["nonce"]
    assert id_token["aud"] == [client_id]
    assert (
        id_token["sub"]
        == "7c373c0a53f219d339a3e9255695101ad4c834005bf91c2e43a7548e68c7ca95"
    )
