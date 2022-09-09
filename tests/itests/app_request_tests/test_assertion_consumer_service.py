import random
import string
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from inge6.config import get_settings
from inge6.provider import Provider
from inge6.main import app


def test_acs_fail_empty_params():

    client = TestClient(app)

    # First three calls no problem
    resp = client.get("/acs")
    assert resp.status_code == 401
    assert "User not authorized" in resp.text


def test_acs_fail_random_state_artifact(
    mocker, redis_mock
):  # pylint: disable=unused-argument
    mock_provider = Provider(settings=get_settings())

    mocker.patch("inge6.main.PROVIDER", mock_provider)
    client = TestClient(app)

    # First three calls no problem
    random_state = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    fake_artifact = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    resp = client.get(f"/acs?RelayState={random_state}&SAMLart={fake_artifact}")
    assert resp.status_code == 404
    assert "Session expired, user not authorized" in resp.text


def test_acs_succes_metaredirect_response(mocker, redis_mock):

    mock_provider = Provider(settings=get_settings(), redis_client=redis_mock)
    mocker.patch(
        "inge6.provider.hget_from_redis",
    )

    mock_provider.oidc.authorize = MagicMock()

    mocker.patch("inge6.provider.cache_artifact")
    mocker.patch("inge6.provider.cache_code_challenge")
    mocker.patch("inge6.provider.urlparse")
    mocker.patch("inge6.provider.parse_qs")

    mocker.patch("inge6.main.PROVIDER", mock_provider)
    client = TestClient(app)

    random_state = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    fake_artifact = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
    resp = client.get(f"/acs?RelayState={random_state}&SAMLart={fake_artifact}")
    assert resp.status_code == 200
    assert '<meta http-equiv="refresh" content="0;url=<MagicMock ' in resp.text
    assert 'Page not redirecting? Click <a href="<MagicMock ' in resp.text
