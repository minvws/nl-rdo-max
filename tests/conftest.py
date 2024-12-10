# pylint:disable=too-few-public-methods
import pytest


def pytest_addoption(parser, pluginmanager):
    parser.addoption(
        "--docker",
        action="store_true",
        default=False,
        help="Flags whether pytest is ran inside a docker container",
    )


@pytest.fixture
def inside_docker(pytestconfig):
    return pytestconfig.getoption("docker")
