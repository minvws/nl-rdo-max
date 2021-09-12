import urllib

from fastapi.testclient import TestClient

from inge6.main import app


# pylint: disable=unused-argument, redefined-outer-name
def test_authorize_request_post(mock_clients_db, redis_mock, tvs_config):
    client = TestClient(app)

    authorize_params = {
        'client_id': "test_client",
        'redirect_uri': "http://localhost:3000/login",
        'response_type': "code",
        'nonce': "n-0S6_WzA2Mj",
        'state': "af0ifjsldkj",
        'scope': "openid",
        'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        'code_challenge_method': "S256",
    }
    query_params: str = urllib.parse.urlencode(authorize_params)
    response = client.get(f'/authorize?{query_params}')

    assert response.status_code == 200
    assert "SAMLRequest" in response.content.decode()
    assert "RelayState" in response.content.decode()
    assert "SAMLForm" in response.content.decode()


# pylint: disable=unused-argument, redefined-outer-name
def test_authorize_request_redirect(mock_clients_db, digid_config, digid_mock_disable):
    client = TestClient(app)

    authorize_params = {
        'client_id': "test_client",
        'redirect_uri': "http://localhost:3000/login",
        'response_type': "code",
        'nonce': "n-0S6_WzA2Mj",
        'state': "af0ifjsldkj",
        'scope': "openid",
        'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        'code_challenge_method': "S256",
    }
    query_params: str = urllib.parse.urlencode(authorize_params)
    response = client.get(f'/authorize?{query_params}', allow_redirects=False)

    assert response.status_code == 307
    assert "SAMLRequest" in response.headers['location']
    assert "RelayState" in response.headers['location']
    assert "Signature" in response.headers['location']
    assert "SigAlg" in response.headers['location']
