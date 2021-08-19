import pytest

from inge6.cache import get_redis_client
from inge6.exceptions import TooBusyError, TooManyRequestsFromOrigin
from inge6.rate_limiter import rate_limit_test
from inge6.config import settings

@pytest.fixture
def disable_overflow():
    tmp = settings.overflow_idp
    settings.overflow_idp = 'false'
    yield
    settings.overflow_idp = tmp

# pylint: disable=unused-argument
def test_rate_limiter_ip_block(redis_mock):
    with pytest.raises(TooManyRequestsFromOrigin):
        rate_limit_test('0.0.0.0')
        rate_limit_test('0.0.0.0')

#pylint: disable=unused-argument, redefined-outer-name
def test_rate_limiter_user_limit(redis_mock, disable_overflow):
    get_redis_client().set('user_limit_key', 3)
    with pytest.raises(TooBusyError):
        rate_limit_test('0.0.0.1')
        rate_limit_test('0.0.0.2')
        rate_limit_test('0.0.0.3')
        rate_limit_test('0.0.0.4')

# pylint: disable=unused-argument
def test_rate_limiter_below_user_limit(redis_mock):
    get_redis_client().set('user_limit_key', 3)
    rate_limit_test('0.0.0.1')
    rate_limit_test('0.0.0.2')


