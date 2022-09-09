import urllib

from fastapi.testclient import TestClient

from inge6.main import app
from inge6.provider import Provider
from inge6.constants import SomethingWrongReason
from ...test_utils import get_settings


# pylint: disable=unused-argument, redefined-outer-name
def test_authorize_request_post(
    redis_mock, tvs_config, default_authorize_request_dict, mocker
):
    mock_provider = Provider(settings=get_settings())
    mock_provider.clients = {
        "test_client": {
            "token_endpoint_auth_method": "none",
            "redirect_uris": [
                "http://localhost:3000/login",
            ],
            "response_types": ["code"],
        }
    }

    mocker.patch("inge6.main.PROVIDER", mock_provider)
    client = TestClient(app)

    query_params: str = urllib.parse.urlencode(default_authorize_request_dict)
    response = client.get(f"/authorize?{query_params}")

    assert response.status_code == 200
    assert "SAMLRequest" in response.content.decode()
    assert "RelayState" in response.content.decode()
    assert "SAMLForm" in response.content.decode()


# pylint: disable=unused-argument, redefined-outer-name
def test_authorize_request_redirect(
    digid_config, mocker, default_authorize_request_dict
):
    mock_provider = Provider(settings=get_settings({"mock_digid": False}))
    mock_provider.clients = {
        "test_client": {
            "token_endpoint_auth_method": "none",
            "redirect_uris": [
                "http://localhost:3000/login",
            ],
            "response_types": ["code"],
        }
    }
    mocker.patch("inge6.main.PROVIDER", mock_provider)

    client = TestClient(app)

    query_params: str = urllib.parse.urlencode(default_authorize_request_dict)
    response = client.get(f"/authorize?{query_params}", allow_redirects=False)

    assert response.status_code == 307
    assert "SAMLRequest" in response.headers["location"]
    assert "RelayState" in response.headers["location"]
    assert "Signature" in response.headers["location"]
    assert "SigAlg" in response.headers["location"]


# pylint: disable=unused-argument, redefined-outer-name
def test_authorize_outage(
    redis_mock, mocker, digid_config, default_authorize_request_dict
):
    outage_key = "inge6:outage"

    mock_provider = Provider(
        settings=get_settings({"mock_digid": False, "ratelimit.outage_key": outage_key})
    )
    mock_provider.clients = {
        "test_client": {
            "token_endpoint_auth_method": "none",
            "redirect_uris": [
                "http://localhost:3000/login",
            ],
            "response_types": ["code"],
        }
    }

    mocker.patch("inge6.main.PROVIDER", mock_provider)
    redis_mock.set(outage_key, "1")

    client = TestClient(app)

    query_params: str = urllib.parse.urlencode(default_authorize_request_dict)
    response = client.get(f"/authorize?{query_params}", allow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"].startswith("/sorry-something-went-wrong")
    assert SomethingWrongReason.OUTAGE.value in response.headers["location"]


# pylint: disable=unused-argument, redefined-outer-name
def test_authorize_authbyprxy_disabled(
    redis_mock, mocker, digid_config, default_authorize_request_dict
):
    mock_provider = Provider(settings=get_settings({"mock_digid": False}))
    mock_provider.clients = {
        "test_client": {
            "token_endpoint_auth_method": "none",
            "redirect_uris": [
                "http://localhost:3000/login",
            ],
            "response_types": ["code"],
        }
    }

    mocker.patch("inge6.main.PROVIDER", mock_provider)

    client = TestClient(app)

    default_authorize_request_dict["scope"] = "openid authorization_by_proxy"
    query_params: str = urllib.parse.urlencode(default_authorize_request_dict)
    response = client.get(f"/authorize?{query_params}", allow_redirects=False)

    assert response.status_code == 307
    assert response.headers["location"].startswith("/sorry-something-went-wrong")
    assert (
        SomethingWrongReason.AUTH_BY_PROXY_DISABLED.value
        in response.headers["location"]
    )


def test_authorize_ratelimit(mocker, redis_mock, default_authorize_request_dict):
    mock_provider = Provider(
        settings=get_settings(
            {
                "mock_digid": False,
                "primary_idp_key": "inge6:primary_idp",
                "ratelimit.user_limit_key": "user_limit_key",
            }
        )
    )

    mock_provider.redis_client = redis_mock
    mock_provider.redis_client.set("user_limit_key", 3)
    mock_provider.redis_client.set("inge6:primary_idp", "tvs")

    mocker.patch("inge6.main.PROVIDER", mock_provider)
    client = TestClient(app)

    query_params: str = urllib.parse.urlencode(default_authorize_request_dict)

    # First three calls no problem
    resp = client.get(f"/authorize?{query_params}", allow_redirects=False)
    assert not (
        "location" in resp.headers
        and resp.headers["location"].startswith("/sorry-something-went-wrong")
    )

    resp = client.get(f"/authorize?{query_params}", allow_redirects=False)
    assert not (
        "location" in resp.headers
        and resp.headers["location"].startswith("/sorry-something-went-wrong")
    )

    resp = client.get(f"/authorize?{query_params}", allow_redirects=False)
    assert not (
        "location" in resp.headers
        and resp.headers["location"].startswith("/sorry-something-went-wrong")
    )

    # Fourth is the limit.
    resp = client.get(f"/authorize?{query_params}", allow_redirects=False)
    assert resp.headers["location"].startswith("/sorry-something-went-wrong")
    assert SomethingWrongReason.TOO_MANY_REQUEST.value in resp.headers["location"]
