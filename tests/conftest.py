import pytest
from inge6 import cache
from inge6.config import settings
from inge6.cache import get_redis_client

@pytest.fixture
def redis_mock(redisdb):
    # pylint: disable=W0212
    # Access to a protected member
    client = cache._REDIS_CLIENT
    cache._REDIS_CLIENT = redisdb
    yield
    cache._REDIS_CLIENT = client

# pylint: disable=redefined-outer-name, unused-argument
@pytest.fixture
def digid_config(redis_mock):
    get_redis_client().set(settings.connect_to_idp_key, 'digid')

# pylint: disable=redefined-outer-name, unused-argument
@pytest.fixture
def tvs_config(redis_mock):
    get_redis_client().set(settings.connect_to_idp_key, 'tvs')

@pytest.fixture
def disable_digid_mock():
    tmp = settings.mock_digid
    settings.mock_digid = 'false'
    yield
    settings.mock_digid = tmp
