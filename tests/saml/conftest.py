import pytest

from inge6.provider import Provider
from inge6.config import settings

@pytest.fixture
def provider() -> Provider:
    yield Provider()

@pytest.fixture
def digid_config():
    tmp = settings.connect_to_idp
    settings.connect_to_idp = 'digid'
    yield
    settings.connect_to_idp = tmp

@pytest.fixture
def tvs_config():
    tmp = settings.connect_to_idp
    settings.connect_to_idp = 'tvs'
    yield
    settings.connect_to_idp = tmp

@pytest.fixture
def disable_digid_mock():
    tmp = settings.mock_digid
    settings.mock_digid = 'false'
    yield
    settings.mock_digid = tmp
