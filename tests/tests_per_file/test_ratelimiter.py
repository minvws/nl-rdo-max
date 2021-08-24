import pytest

from inge6.cache import get_redis_client
from inge6.exceptions import TooBusyError, TooManyRequestsFromOrigin
from inge6.rate_limiter import rate_limit_test
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

# pylint: disable=unused-argument
def test_rate_limiter_ip_block(redis_mock, digid_config):
    with pytest.raises(TooManyRequestsFromOrigin):
        rate_limit_test('0.0.0.0')
        rate_limit_test('0.0.0.0')

#pylint: disable=unused-argument, redefined-outer-name
def test_rate_limiter_user_limit(redis_mock, fake_redis_user_limit_key, disable_overflow, digid_config):
    get_redis_client().set('user_limit_key', 3)

    rate_limit_test('0.0.0.1')
    rate_limit_test('0.0.0.2')
    rate_limit_test('0.0.0.3')
    with pytest.raises(TooBusyError):
        rate_limit_test('0.0.0.4')
