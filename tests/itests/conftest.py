import os
import random
import string
import uuid

import nacl
import pytest
from dependency_injector import providers, containers
from fastapi.testclient import TestClient
from app.application import create_fastapi_app
from app.dependency_injection.config import get_config, RouterConfig
from app.dependency_injection.container import Container
from app.dependency_injection.pyop_services import PyopServices
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder
from pytest_redis import factories

from app.misc.lazy import Lazy


class PyopOverridingContainer(containers.DeclarativeContainer):
    clients = providers.Object({})


redis_port = 6379
redis_config = factories.redis_noproc(port=redis_port)
redis = factories.redisdb("redis_config")


@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig):
    return os.path.join(str(pytestconfig.rootdir), "", "docker-compose.yml")


@pytest.fixture
def config():
    yield get_config("tests/max.conf.test")


@pytest.fixture
def app_mode_legacy(config, pynacl_keys):
    config["app"]["app_mode"] = "legacy"
    config["app"]["jwe_encryption"] = "ed25519"
    config["app"]["userinfo_service"] = "cc"
    config["app"]["jwe_sign_nacl_priv_key"] = pynacl_keys["server_key"]


@pytest.fixture
def app_mode_default(config):
    config["app"]["app_mode"] = ""
    config["app"]["jwe_encryption"] = "rsa"
    config["app"]["userinfo_service"] = "cc"


@pytest.fixture
def pynacl_keys():
    server_key = PrivateKey.generate()
    client_key = PrivateKey.generate()
    return {
        "server_key": server_key.encode(encoder=Base64Encoder).decode("utf-8"),
        "server_pub": server_key.public_key.encode(encoder=Base64Encoder).decode("utf-8"),
        "client_key": client_key.encode(encoder=Base64Encoder).decode("utf-8"),
        "client_pub": client_key.public_key.encode(encoder=Base64Encoder).decode("utf-8"),
    }


@pytest.fixture
def legacy_client(client, pynacl_keys):
    lc = client[1].copy()
    del lc["client_certificate_path"]
    lc["client_public_nacl_key"] = pynacl_keys["client_pub"]
    return client[0], lc


@pytest.fixture
def client():
    return str(uuid.uuid4()), {
        "name": "Test Client",
        "external_id": "87654321",
        "token_endpoint_auth_method": "none",
        "redirect_uris": [
            "http://localhost:3000/login"
        ],
        "response_types": ["code"],
        "client_certificate_path": "secrets/clients/test_client/test_client.crt"
    }


@pytest.fixture
def lazy_container(config, legacy_client, client):
    def _container() -> Container:
        c = Container()
        p = PyopOverridingContainer()
        c.pyop_services.override(p)
        if config["app"]["app_mode"] == "legacy":
            p.clients.override(providers.Object(dict([legacy_client])))
        else:
            p.clients.override(providers.Object(dict([client])))
        return c

    yield Lazy(lambda: _container())


@pytest.fixture
def lazy_app(docker_services, config, lazy_container):
    config["oidc"]["issuer"] = "https://localhost:" + str(random.randint(13000, 14000))
    config["app"]["user_authentication_sym_key"] = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE).hex()

    def _app() -> TestClient:
        return TestClient(create_fastapi_app(config, lazy_container.value))
    yield Lazy(lambda: _app())


# noinspection PyShadowingNames
@pytest.fixture
# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument
def redis_mock(docker_services, redis):
    redis.config_set("notify-keyspace-events", "AKE")
    yield redis