import logging
import time
import pytest

from inge6 import config, constants
from inge6.cache import RedisCache


@pytest.fixture
def debuggable_redis_cache_fast_expire(redis_mock):
    settings = config.get_settings()

    tmp_debugger = settings.redis.enable_debugger
    tmp_ttl = settings.redis.object_ttl
    settings.redis.enable_debugger = True
    settings.redis.object_ttl = 1

    redis_cache = RedisCache(settings=settings, redis_client=redis_mock)
    redis_mock.config_set("notify-keyspace-events", "AKE")
    yield redis_cache
    settings.redis.enable_debugger = tmp_debugger
    settings.redis.object_ttl = tmp_ttl


@pytest.fixture
def capture_logging(caplog):
    caplog.set_level(logging.DEBUG)
    yield caplog
    caplog.clear()


# pylint: disable=redefined-outer-name, unused-argument
def test_redis_debugger_no_retrieve_with_redis_cache_hset(
    capture_logging, debuggable_redis_cache_fast_expire
):
    # Set value but don't retrieve
    debuggable_redis_cache_fast_expire.hset(
        "7f2fa9a48d8f4aef95a5fffb695d8f20",
        constants.RedisKeys.CC_CM.value,
        "test-value",
    )
    time.sleep(2)

    # Should be in log:
    assert (
        "Attempting retrieval of debug-key: tvs-connect:retrieved:tvs-connect:7f2fa9a48d8f4aef95a5fffb695d8f20"
        in capture_logging.text
    )
    assert (
        "Key tvs-connect:7f2fa9a48d8f4aef95a5fffb695d8f20:cc_cm has expired, but was never retrieved"
        in capture_logging.text
    )


# pylint: disable=redefined-outer-name, unused-argument
def test_redis_debugger_retrieve_with_redis_cache_hget(
    capture_logging, debuggable_redis_cache_fast_expire
):

    # Set value and retrieve:
    debuggable_redis_cache_fast_expire.hset(
        "1a1bc9t25d2f4oly52i3pabc241d1f10",
        constants.RedisKeys.CC_CM.value,
        "test-value",
    )
    debuggable_redis_cache_fast_expire.hget(
        "1a1bc9t25d2f4oly52i3pabc241d1f10", constants.RedisKeys.CC_CM.value
    )
    time.sleep(2)

    # Should not be in log:
    assert (
        "Attempting retrieval of debug-key: tvs-connect:retrieved:tvs-connect:1a1bc9t25d2f4oly52i3pabc241d1f10"
        in capture_logging.text
    )
    assert (
        "Key tvs-connect:1a1bc9t25d2f4oly52i3pabc241d1f10 has expired, but was never retrieved"
        not in capture_logging.text
    )


# pylint: disable=redefined-outer-name, unused-argument
def test_redis_debugger_no_retrieve_with_redis_cache_set(
    capture_logging, debuggable_redis_cache_fast_expire
):
    debuggable_redis_cache_fast_expire.set("test-key", "true")
    time.sleep(2)
    assert (
        "Attempting retrieval of debug-key: tvs-connect:retrieved:tvs-connect:test-key:tvs-connect:test-key"
        in capture_logging.text
    )

    # Should be in log:
    assert (
        "Key tvs-connect:test-key:tvs-connect:test-key has expired, but was never retrieved"
        in capture_logging.text
    )


def test_redis_debugger_no_retrieve_with_redis_cache_get(
    capture_logging, debuggable_redis_cache_fast_expire
):
    debuggable_redis_cache_fast_expire.set("test-key", "true")
    debuggable_redis_cache_fast_expire.get("test-key")
    time.sleep(2)

    assert (
        "Attempting retrieval of debug-key: tvs-connect:retrieved:tvs-connect"
        in capture_logging.text
    )

    # Should not be in log:
    assert (
        "Key tvs-connect:test-key has expired, but was never retrieved"
        not in capture_logging.text
    )
