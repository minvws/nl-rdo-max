import nacl
import pytest
import random

from dependency_injector import providers, containers
from fastapi.testclient import TestClient
from pytest_redis import factories
from pytest_docker.plugin import get_docker_services, containers_scope

from app.application import create_fastapi_app
from app.dependency_injection.container import Container
from app.misc.lazy import Lazy


class PyopOverridingContainer(containers.DeclarativeContainer):
    # pylint:disable=c-extension-no-member
    clients = providers.Object({})


REDIS_PORT = 6379
redis_config = factories.redis_noproc(port=REDIS_PORT)
redis = factories.redisdb("redis_config")


@pytest.fixture
def config_with_cc_userinfo_service(config):
    config["app"]["userinfo_service"] = "cc"
    return config


@pytest.fixture
def container_overrides():
    return []


@pytest.fixture
def pyop_override(config, test_clients, container_overrides):
    def override_pyop(container):
        pyop = PyopOverridingContainer()
        pyop.clients.override(
            providers.Object(test_clients)
        )  # pylint:disable=c-extension-no-member
        container.pyop_services.override(pyop)

    container_overrides.append(override_pyop)


@pytest.fixture
def lazy_container(config, container_overrides, pyop_override):
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
