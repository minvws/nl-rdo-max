from typing import Dict, Any, Tuple

import pytest
from jwcrypto.jwk import JWK

from app.dependency_injection.config import get_config
from app.models.certificate_with_jwk import CertificateWithJWK
from tests.utils import make_test_certificate


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
def full_test_client_without_client_auth() -> (
    Tuple[str, dict[str, Any], CertificateWithJWK, JWK]
):
    cert, private_key = make_test_certificate()

    return (
        "test_client_without_client_auth",
        {
            "name": "Test Client without authentication",
            "external_id": "87654321",
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["http://localhost:3000/login"],
            "response_types": ["code"],
            "certificate": cert,
            "exclude_login_methods": ["yivi"],
            "client_authentication_method": "none",
        },
        cert,
        private_key,
    )


@pytest.fixture
def full_test_client() -> Tuple[str, dict[str, Any], CertificateWithJWK, JWK]:
    cert, private_key = make_test_certificate()

    return (
        "test_client",
        {
            "name": "Test Client",
            "external_id": "87654321",
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["http://localhost:3000/login"],
            "response_types": ["code"],
            "certificate": cert,
            "exclude_login_methods": ["yivi"],
            "client_authentication_method": "private_key_jwt",
        },
        cert,
        private_key,
    )


@pytest.fixture
def test_client_id(full_test_client) -> str:
    return full_test_client[0]


@pytest.fixture
def test_client(full_test_client) -> Dict[str, Any]:
    return full_test_client[1]


@pytest.fixture
def test_client_certificate(full_test_client) -> CertificateWithJWK:
    return full_test_client[2]


@pytest.fixture
def test_client_private_key(full_test_client) -> JWK:
    return full_test_client[3]


@pytest.fixture
def test_client_without_client_auth_id(full_test_client_without_client_auth) -> str:
    return full_test_client_without_client_auth[0]


@pytest.fixture
def test_client_without_client_auth(
    full_test_client_without_client_auth,
) -> Dict[str, Any]:
    return full_test_client_without_client_auth[1]


@pytest.fixture
def test_client_without_client_auth_certificate(
    full_test_client_without_client_auth,
) -> CertificateWithJWK:
    return full_test_client_without_client_auth[2]


@pytest.fixture
def test_client_without_client_auth_private_key(
    full_test_client_without_client_auth,
) -> JWK:
    return full_test_client_without_client_auth[3]


@pytest.fixture
def test_clients(
    test_client_id,
    test_client,
    test_client_without_client_auth_id,
    test_client_without_client_auth,
) -> Dict[str, Dict[str, Any]]:
    return {
        test_client_without_client_auth_id: test_client_without_client_auth,
        test_client_id: test_client,
    }
