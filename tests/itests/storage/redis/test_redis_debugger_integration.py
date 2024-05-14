import logging
import time

import pytest

from app.storage.redis.redis_debugger import RedisGetDebuggerFactory


@pytest.fixture
def redis_caplog(caplog):
    caplog.set_level(logging.DEBUG, logger="app.storage.redis")
    yield caplog
    caplog.clear()


@pytest.fixture
def debuggable_redis_cache_fast_expire(redis_mock):
    rgdf = RedisGetDebuggerFactory(redis_mock, "info", 1, "debug_namespace")
    rgd = rgdf.create()
    rgd.start()


def test_listen_for_expiration_events_when_not_retrieved(
    debuggable_redis_cache_fast_expire,  # pylint:disable=unused-argument, redefined-outer-name
    redis_caplog,  # pylint:disable=redefined-outer-name
    redis_mock,
):
    redis_mock.set("debug_namespace:key", "value", ex=1)
    time.sleep(1.3)
    # Should be in log:
    assert (
        "Attempting retrieval of debug-key:"
        " debug_namespace:retrieved:debug_namespace:key" in redis_caplog.text
    )
    assert (
        "Key debug_namespace:key has expired, but was never retrieved"
        in redis_caplog.text
    )


def test_listen_for_expiration_events(
    debuggable_redis_cache_fast_expire,  # pylint:disable=unused-argument, redefined-outer-name
    redis_caplog,  # pylint:disable=redefined-outer-name
    redis_mock,
):
    redis_mock.set("debug_namespace:key", "value", ex=1)
    redis_mock.set("debug_namespace:retrieved:debug_namespace:key", "bla")
    time.sleep(1.1)
    # Should be in log:
    assert (
        "Attempting retrieval of debug-key:"
        " debug_namespace:retrieved:debug_namespace:key" in redis_caplog.text
    )
    assert (
        "Key debug_namespace:key has expired, but was never retrieved"
        not in redis_caplog.text
    )
