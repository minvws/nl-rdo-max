import nacl
import pytest
import random
import uuid

from dependency_injector import providers, containers
from fastapi.testclient import TestClient
from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey
from pytest_redis import factories
from pytest_docker.plugin import get_docker_services, containers_scope

from app.application import create_fastapi_app
from app.dependency_injection.config import get_config, RouterConfig
from app.dependency_injection.container import Container
from app.misc.lazy import Lazy
from app.services.userinfo.userinfo_service import UserinfoService


class PyopOverridingContainer(containers.DeclarativeContainer):
    # pylint:disable=c-extension-no-member
    clients = providers.Object({})


REDIS_PORT = 16379
redis_config = factories.redis_noproc(port=REDIS_PORT)
redis = factories.redisdb("redis_config")


@pytest.fixture
def config(inside_docker):
    yield get_config(
        "tests/max.test.conf.docker" if inside_docker else "tests/max.test.conf"
    )


@pytest.fixture
# pylint:disable=redefined-outer-name
def saml_userinfo_service(config, pynacl_keys):
    config["app"]["userinfo_service"] = "cc"
    config["jwe"]["jwe_sign_nacl_priv_key"] = pynacl_keys["server_key"]


@pytest.fixture
def pynacl_keys():
    server_key = PrivateKey.generate()
    client_key = PrivateKey.generate()
    return {
        "server_key": server_key.encode(encoder=Base64Encoder).decode("utf-8"),
        "server_pub": server_key.public_key.encode(encoder=Base64Encoder).decode(
            "utf-8"
        ),
        "client_key": client_key.encode(encoder=Base64Encoder).decode("utf-8"),
        "client_pub": client_key.public_key.encode(encoder=Base64Encoder).decode(
            "utf-8"
        ),
    }


@pytest.fixture
def legacy_client(
    client,  # pylint:disable=redefined-outer-name
    pynacl_keys,  # pylint:disable=redefined-outer-name
    tmp_path,
):
    fp = tmp_path.joinpath("client_pub_key.pub")
    with open(fp, "w") as file:
        file.write(pynacl_keys["client_pub"])
    legacy_c = client[1].copy()
    legacy_c["client_public_key_path"] = str(fp)
    legacy_c["pubkey_type"] = "x25519"
    return client[0], legacy_c


@pytest.fixture
def client():
    return str(uuid.uuid4()), {
        "name": "Test Client",
        "external_id": "87654321",
        "token_endpoint_auth_method": "none",
        "redirect_uris": ["http://localhost:3000/login"],
        "response_types": ["code"],
        "pubkey_type": "RSA",
        "client_public_key_path": "secrets/clients/test_client/test_client.crt",
        "client_authentication_method": "none",
    }


@pytest.fixture
def container_overrides():
    return []


@pytest.fixture
def pyop_override(config, legacy_client, client, container_overrides):
    def override_pyop(container):
        pyop = PyopOverridingContainer()
        pyop.clients.override(
            providers.Object(dict([client]))
        )  # pylint:disable=c-extension-no-member
        container.pyop_services.override(pyop)

    container_overrides.append(override_pyop)


@pytest.fixture
# pylint:disable=redefined-outer-name
def lazy_container(config, legacy_client, client, container_overrides, pyop_override):
    def _container() -> Container:
        cont = Container()
        pyop = PyopOverridingContainer()
        cont.pyop_services.override(pyop)
        for override in container_overrides:
            override(cont)
        return cont

    yield Lazy(_container)


@pytest.fixture
# pylint:disable=redefined-outer-name, unused-argument
def lazy_app(prepare_docker_services, config, lazy_container):
    config["oidc"]["issuer"] = "https://localhost:" + str(random.randint(13000, 14000))
    config["app"]["user_authentication_sym_key"] = nacl.utils.random(
        nacl.secret.SecretBox.KEY_SIZE
    ).hex()

    def _app() -> TestClient:
        return TestClient(create_fastapi_app(config, lazy_container.value))

    yield Lazy(_app)


# noinspection PyShadowingNames
@pytest.fixture
# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument
def redis_mock(prepare_docker_services, redis):
    redis.config_set("notify-keyspace-events", "AKE")
    yield redis


@pytest.fixture(scope=containers_scope)
def prepare_docker_services(
    inside_docker,
    docker_compose_command,
    docker_compose_file,
    docker_compose_project_name,
    docker_setup,
    docker_cleanup,
):
    if inside_docker:
        yield
    else:
        with get_docker_services(
            docker_compose_command,
            docker_compose_file,
            docker_compose_project_name,
            docker_setup,
            docker_cleanup,
        ) as docker_service:
            yield docker_service
