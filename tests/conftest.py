import pytest
from inge6 import cache

@pytest.fixture
def redis_mock(redisdb):
    # pylint: disable=W0212
    # Access to a protected member
    client = cache._REDIS_CLIENT
    cache._REDIS_CLIENT = redisdb
    yield
    cache._REDIS_CLIENT = client
