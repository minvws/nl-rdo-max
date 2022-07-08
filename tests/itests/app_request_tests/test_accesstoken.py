import json

from fastapi.testclient import TestClient

from inge6.config import get_settings
from inge6.models import JWTError
from inge6.provider import Provider
from inge6.main import app


def test_accesstoken_userlogin_fails_response(mocker):
    def raise_jwt_error(*_, **__):
        raise JWTError(
            error="saml_authn_failed",
            error_description="User failed to authenticate",
        )

    mock_provider = Provider(settings=get_settings())

    # pylint: disable=protected-access
    mock_provider._resolve_artifact = raise_jwt_error

    mocker.patch(
        "inge6.provider.hget_from_redis",
        return_value={
            "artifact": "",
            "id_provider": "",
            "authorization_by_proxy": "",
        },
    )
    mocker.patch("inge6.provider.accesstoken", return_value="")
    mocker.patch("inge6.provider.parse_qs", return_value={"code": [""]})
    mocker.patch("inge6.main.PROVIDER", mock_provider)
    client = TestClient(app)

    # First three calls no problem
    resp = client.post("/accesstoken", data={})
    assert resp.status_code == 400
    assert json.loads(resp.content) == {
        "error": "saml_authn_failed",
        "error_description": "User failed to authenticate",
    }
