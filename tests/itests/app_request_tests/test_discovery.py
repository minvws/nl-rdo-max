import json

from fastapi.testclient import TestClient
from inge6.config import get_settings
from inge6.main import app


def test_auto_discovery():
    client = TestClient(app)

    json_content = json.loads(client.get(".well-known/openid-configuration").text)
    assert json_content["issuer"] == get_settings().issuer
