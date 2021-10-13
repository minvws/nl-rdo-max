import time
import pytest

from inge6.exceptions import TooBusyError, TooManyRequestsFromOrigin
from inge6.config import get_settings
from inge6.rate_limiter import RateLimiter

@pytest.fixture
def rate_limiter(redis_mock):
    yield RateLimiter(get_settings(), redis_mock)

#pylint: disable=unused-argument, redefined-outer-name
def test_rate_limiter_user_limit(redis_mock, rate_limiter, fake_redis_user_limit_key, disable_overflow, digid_config):
    redis_mock.set('user_limit_key', 3)

    rate_limiter.rate_limit_test('0.0.0.1')
    rate_limiter.rate_limit_test('0.0.0.2')
    rate_limiter.rate_limit_test('0.0.0.3')
    with pytest.raises(TooBusyError):
        rate_limiter.rate_limit_test('0.0.0.4')

#pylint: disable=unused-argument, redefined-outer-name
def test_rate_limiter_overflow(redis_mock, rate_limiter, fake_redis_user_limit_key, fake_redis_overflow_userlimit_key):
    redis_mock.set('tvs:primary_idp', 'tvs')
    redis_mock.set('tvs:overflow_idp', 'digid')
    redis_mock.set('user_limit_key', 1)
    redis_mock.set('overflow_userlimit', 3)

    active_idp = rate_limiter.rate_limit_test('0.0.0.1')
    assert active_idp == 'tvs'
    active_idp = rate_limiter.rate_limit_test('0.0.0.2')
    assert active_idp == 'digid'
    active_idp = rate_limiter.rate_limit_test('0.0.0.3')
    assert active_idp == 'digid'
    active_idp = rate_limiter.rate_limit_test('0.0.0.4')
    assert active_idp == 'digid'



#pylint: disable=unused-argument, redefined-outer-name
def test_rate_limiter_overflow_limit_0(redis_mock, rate_limiter, fake_redis_user_limit_key, fake_redis_overflow_userlimit_key):
    redis_mock.set('tvs:primary_idp', 'tvs')
    redis_mock.set('tvs:overflow_idp', 'digid')
    redis_mock.set('user_limit_key', 0)

    active_idp = rate_limiter.rate_limit_test('0.0.0.1')
    assert active_idp == 'digid'


#pylint: disable=unused-argument, redefined-outer-name
def test_multiple_attempts_per_ip(redis_mock, rate_limiter):
    redis_mock.set('tvs:primary_idp', 'tvs')
    tmp = get_settings().ratelimit.nof_attempts_s
    get_settings().ratelimit.nof_attempts_s = 3
    rate_limiter.rate_limit_test('0.0.0.1')
    rate_limiter.rate_limit_test('0.0.0.1')
    rate_limiter.rate_limit_test('0.0.0.1')

    with pytest.raises(TooManyRequestsFromOrigin):
        rate_limiter.rate_limit_test('0.0.0.1')

    get_settings().ratelimit.nof_attempts_s = tmp


#pylint: disable=unused-argument, redefined-outer-name
def test_multiple_attempts_per_ip_default(redis_mock, rate_limiter):
    redis_mock.set('tvs:primary_idp', 'tvs')
    tmp_attempts = get_settings().ratelimit.nof_attempts_s
    del get_settings().ratelimit.nof_attempts_s

    ip_address = '0.0.0.1'
    rate_limiter.rate_limit_test(ip_address)
    with pytest.raises(TooManyRequestsFromOrigin):
        rate_limiter.rate_limit_test(ip_address)

    get_settings().ratelimit.nof_attempts_s = tmp_attempts

#pylint: disable=unused-argument, redefined-outer-name
def test_ratelimit_ip_ttl(redis_mock, rate_limiter):
    redis_mock.set('tvs:primary_idp', 'tvs')
    tmp_ip_ttl = get_settings().ratelimit.ip_expire_in_s
    get_settings().ratelimit.ip_expire_in_s = 1

    ip_address = '0.0.0.1'
    ip_key = "tvs:ipv4:" + ip_address
    rate_limiter.rate_limit_test(ip_address)

    assert redis_mock.get(ip_key) is not None
    time.sleep(1)
    assert redis_mock.get(ip_key) is None

    get_settings().ratelimit.ip_expire_in_s = tmp_ip_ttl


#pylint: disable=unused-argument, redefined-outer-name
def test_ratelimit_ip_ttl_multi_attempts(redis_mock, rate_limiter):
    """
        This test shows that the TTL of an IP address in redis does not refresh when a new login attempt is requested.
    """
    redis_mock.set('tvs:primary_idp', 'tvs')
    tmp_ip_ttl = get_settings().ratelimit.ip_expire_in_s
    get_settings().ratelimit.ip_expire_in_s = 3

    ip_address = '0.0.0.1'
    ip_key = "tvs:ipv4:" + ip_address
    rate_limiter.rate_limit_test(ip_address)
    assert redis_mock.ttl(ip_key) == 3
    time.sleep(1)
    rate_limiter.rate_limit_test(ip_address)
    rate_limiter.rate_limit_test(ip_address)
    assert redis_mock.ttl(ip_key) <= 2


    get_settings().ratelimit.ip_expire_in_s = tmp_ip_ttl
