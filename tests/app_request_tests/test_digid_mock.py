from fastapi.testclient import TestClient

from inge6.main import app

def test_login_digid():
    client = TestClient(app)
    response = client.get("/login-digid?force_digid=1&state=%22%3E%3Cscript%3Ealert(%27XSS%27)%3C%2fscript%3E")
    assert "<script>" not in response.text

def test_digid_mock():
    client = TestClient(app)
    form_data = {
        "SAMLRequest": "saml",
        "RelayState": "an5dz onmouseover=alert(1) style=position: absolute;width:100%;height:100%;top:0;left:0; mhsb0"
    }
    response = client.post("/digid-mock?state=638a16414ee8dfaadf1a4d64cc9d2fba7ddb29b5f6f5849f3f6f1cbec9b44a75", data=form_data)
    assert 'value="an5dz onmouseover=alert(1)' in response.text
