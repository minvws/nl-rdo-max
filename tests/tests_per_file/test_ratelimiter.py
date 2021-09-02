import pytest

from inge6.cache import get_redis_client
from inge6.exceptions import TooBusyError, TooManyRequestsFromOrigin
from inge6.rate_limiter import rate_limit_test

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

def test_rate_limiter_overflow(redis_mock, fake_redis_user_limit_key, fake_redis_overflow_userlimit_key):
    get_redis_client().set('tvs:connect_to_idp', 'tvs')
    get_redis_client().set('tvs:overflow_idp', 'digid')
    get_redis_client().set('user_limit_key', 1)
    get_redis_client().set('overflow_userlimit', 3)

    active_idp = rate_limit_test('0.0.0.1')
    assert active_idp == 'tvs'
    active_idp = rate_limit_test('0.0.0.2')
    assert active_idp == 'digid'
    active_idp = rate_limit_test('0.0.0.3')
    assert active_idp == 'digid'
    active_idp = rate_limit_test('0.0.0.4')
    assert active_idp == 'digid'
