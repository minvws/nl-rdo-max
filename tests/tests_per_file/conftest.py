import pytest

from inge6.cache import get_redis_client
from inge6.config import settings

# pylint: disable=unused-argument
@pytest.fixture
def disable_overflow(redis_mock):
    get_redis_client().set(settings.overflow_idp_key, 'false')

@pytest.fixture
def fake_redis_user_limit_key():
    tmp = settings.ratelimit.user_limit_key
    settings.ratelimit.user_limit_key = 'user_limit_key'
    yield
    settings.ratelimit.user_limit_key = tmp

@pytest.fixture
def fake_redis_overflow_userlimit_key():
    tmp = settings.ratelimit.user_limit_key
    settings.ratelimit.user_limit_key_overflow_idp = 'overflow_user_limit'
    yield
    settings.ratelimit.user_limit_key_overflow_idp = tmp
