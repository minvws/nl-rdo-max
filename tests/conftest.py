from typing import Dict, Any

import pytest
from jwcrypto.jwk import JWK

from app.dependency_injection.config import get_config
from app.misc.utils import clients_from_json, load_jwk

# ID can be found in tests/clients.test.json
TEST_CLIENT_ID = "37692967-0a74-4e91-85ec-a4250e7ad5e8"
TEST_CLIENT_PRIVATE_KEY_PATH = "secrets/clients/test_client/test_client.key"


def pytest_addoption(parser, pluginmanager):
    parser.addoption(
        "--docker",
        action="store_true",
        default=False,
        help="Flags whether pytest is ran inside a docker container",
    )


@pytest.fixture(scope="session")
def inside_docker(pytestconfig):
    return pytestconfig.getoption("docker")


@pytest.fixture
def config(inside_docker):
    yield get_config(
        "tests/max.test.conf.docker" if inside_docker else "tests/max.test.conf"
    )


@pytest.fixture
def test_client_id() -> str:
    return TEST_CLIENT_ID


@pytest.fixture
def test_client(config) -> Dict[str, Any]:
    clients = clients_from_json(config.get("oidc", "clients_file"))
    client = clients[TEST_CLIENT_ID]
    return client


@pytest.fixture
def test_client_private_key() -> JWK:
    return load_jwk(TEST_CLIENT_PRIVATE_KEY_PATH)
