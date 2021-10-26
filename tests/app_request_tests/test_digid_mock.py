import json
import base64

from fastapi.testclient import TestClient

from inge6.main import app
from inge6.models import AuthorizeRequest


def test_login_digid():
    client = TestClient(app)

    auth_req = AuthorizeRequest(
        client_id="test_client",
        redirect_uri="http://localhost:3000/login",
        response_type="code",
        nonce="n-0S6_WzA2Mj",
        state="af0ifjsldkj",
        scope="openid",
        code_challenge="_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw",  # code_verifier = SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        code_challenge_method="S256",
    )
    authn_str = base64.b64encode(json.dumps(auth_req.dict()).encode()).decode()

    response = client.get(
        f"/login-digid?force_digid=1&state=%22%3E%3Cscript%3Ealert(%27XSS%27)%3C%2fscript%3E&idp_name=tvs&authorize_request={authn_str}"
    )
    assert "<script>" not in response.text


def test_digid_mock(default_authorize_request_dict):
    client = TestClient(app)
    form_data = {
        "SAMLRequest": "saml",
        "RelayState": "an5dz onmouseover=alert(1) style=position: absolute;width:100%;height:100%;top:0;left:0; mhsb0",
    }
    auth_req = AuthorizeRequest(**default_authorize_request_dict)
    authn_str = base64.b64encode(json.dumps(auth_req.dict()).encode()).decode()

    response = client.post(
        f"/digid-mock?state=638a16414ee8dfaadf1a4d64cc9d2fba7ddb29b5f6f5849f3f6f1cbec9b44a75&idp_name=tvs&authorize_request={authn_str}",
        data=form_data,
    )
    assert 'value="an5dz onmouseover=alert(1)' in response.text
