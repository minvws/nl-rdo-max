import json
import urllib


import jwt
from fastapi.testclient import TestClient

from inge6.main import app
from inge6.config import settings

# pylint: disable=unused-argument
def test_consume_bsn_and_accesstoken(mock_clients_db, redis_mock, tvs_config):
    client = TestClient(app)
    bsn = "999991772"
    redirect_uri = "http://localhost:3000/login"
    client_id = 'test_client'

    authorize_params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': "code",
        'nonce': "n-0S6_WzA2Mj",
        'state': "af0ifjsldkj",
        'scope': "openid",
        'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        'code_challenge_method': "S256",
    }
    query_params: str = urllib.parse.urlencode(authorize_params)
    resp = client.get(f'/consume_bsn/{bsn}?{query_params}')
    assert resp.status_code == 200

    code = json.loads(resp.text)['code'][0]
    code_verifier = 'SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c'

    acc_req_body = f'client_id={client_id}&redirect_uri={redirect_uri}&code={code}&code_verifier={code_verifier}&grant_type=authorization_code'

    accesstoken_resp = client.post('/accesstoken', acc_req_body)
    assert accesstoken_resp.status_code == 200

    accesstoken = json.loads(accesstoken_resp.content.decode())
    assert accesstoken['expires_in'] == 3600
    assert accesstoken['token_type'] == 'Bearer'
    assert 'access_token' in accesstoken

    id_token = jwt.decode(
        accesstoken['id_token'],
        options = {
            'verify_signature':False
        }
    )
    assert id_token['iss'] == f'https://{settings.issuer}'
    assert id_token['nonce'] == authorize_params['nonce']
    assert id_token['aud'] == [client_id]
    assert id_token['sub'] == '7c373c0a53f219d339a3e9255695101ad4c834005bf91c2e43a7548e68c7ca95'
