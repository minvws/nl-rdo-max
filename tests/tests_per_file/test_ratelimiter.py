import pytest

from inge6.cache import get_redis_client
from inge6.exceptions import TooBusyError, TooManyRequestsFromOrigin
from inge6.config import settings
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
    get_redis_client().set('tvs:primary_idp', 'tvs')
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


def test_rate_limiter_overflow_limit_0(redis_mock, fake_redis_user_limit_key, fake_redis_overflow_userlimit_key):
    get_redis_client().set('tvs:primary_idp', 'tvs')
    get_redis_client().set('tvs:overflow_idp', 'digid')
    get_redis_client().set('user_limit_key', 0)

    active_idp = rate_limit_test('0.0.0.1')
    assert active_idp == 'digid'


def test_multiple_attempts_per_ip(redis_mock):
    get_redis_client().set('tvs:primary_idp', 'tvs')
    tmp = settings.ratelimit.nof_attempts_s
    settings.ratelimit.nof_attempts_s = 3
    rate_limit_test('0.0.0.1')
    rate_limit_test('0.0.0.1')
    rate_limit_test('0.0.0.1')

    with pytest.raises(TooManyRequestsFromOrigin):
        rate_limit_test('0.0.0.1')

    settings.ratelimit.nof_attempts_s = tmp


def test_multiple_attempts_per_ip_default(redis_mock):
    get_redis_client().set('tvs:primary_idp', 'tvs')
    tmp = settings.ratelimit.nof_attempts_s
    del settings.ratelimit.nof_attempts_s

    rate_limit_test('0.0.0.1')
    with pytest.raises(TooManyRequestsFromOrigin):
        rate_limit_test('0.0.0.1')

    settings.ratelimit.nof_attempts_s = tmp
