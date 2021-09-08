import logging
import time
import pytest
from inge6 import constants
from inge6.cache import redis_cache


@pytest.fixture
def fake_expire():
    current_seconds = redis_cache.EXPIRES_IN_S
    redis_cache.EXPIRES_IN_S = 2
    yield
    redis_cache.EXPIRES_IN_S = current_seconds

@pytest.fixture
def capture_logging(caplog):
    caplog.set_level(logging.DEBUG)

    yield caplog
    caplog.clear()

# pylint: disable=redefined-outer-name, unused-argument
def test_redis_debugger_no_retrieve_with_redis_cache_hset(capture_logging, fake_expire):

    # Set value but don't retrieve
    redis_cache.hset("7f2fa9a48d8f4aef95a5fffb695d8f20", constants.RedisKeys.CC_CM.value, "test-value")
    time.sleep(3)

    # Should be in log:
    assert 'Attempting retrieval of debug-key: tvs-connect::retrieved:tvs-connect::' in capture_logging.text
    assert 'Key tvs-connect::7f2fa9a48d8f4aef95a5fffb695d8f20:cc_cm has expired, but was never retrieved' in capture_logging.text

# pylint: disable=redefined-outer-name, unused-argument
def test_redis_debugger_retrieve_with_redis_cache_hget(capture_logging, fake_expire):

    # Set value and retrieve:
    redis_cache.hset("1a1bc9t25d2f4oly52i3pabc241d1f10", constants.RedisKeys.CC_CM.value, "test-value")
    redis_cache.hget("1a1bc9t25d2f4oly52i3pabc241d1f10", constants.RedisKeys.CC_CM.value)
    time.sleep(3)

    # Should not be in log:
    assert 'Attempting retrieval of debug-key: tvs-connect::retrieved:tvs-connect::' in capture_logging.text
    assert 'Key tvs-connect::1a1bc9t25d2f4oly52i3pabc241d1f10:cc_cm has expired, but was never retrieved' not in capture_logging.text

# pylint: disable=redefined-outer-name, unused-argument
def test_redis_debugger_no_retrieve_with_redis_cache_set(capture_logging, fake_expire):
    redis_cache.set('test-key', 'true')
    time.sleep(4)
    assert 'Attempting retrieval of debug-key: tvs-connect::retrieved:tvs-connect::test-key' in capture_logging.text

    # Should be in log:
    assert 'Key tvs-connect::test-key:tvs-connect::test-key has expired, but was never retrieved' in capture_logging.text

def test_redis_debugger_no_retrieve_with_redis_cache_get(capture_logging, fake_expire):
    redis_cache.set('test-key', 'true')
    redis_cache.get('test-key')
    time.sleep(3)

    assert 'Attempting retrieval of debug-key: tvs-connect::retrieved:tvs-connect::test-key' in capture_logging.text

    # Should not be in log:
    assert 'Key tvs-connect::test-key has expired, but was never retrieved' not in capture_logging.text
