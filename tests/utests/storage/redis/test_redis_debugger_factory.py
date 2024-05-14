import logging
from unittest.mock import MagicMock

import pytest

from app.storage.redis.redis_debugger import RedisGetDebuggerFactory


def test_redis_get_debugger_factory():
    redis_client = MagicMock()
    rgdf = RedisGetDebuggerFactory(redis_client, "debug", 5, "default_namespace")
    rgd = rgdf.create()
    assert rgd.redis_client == redis_client
    assert logging.getLevelName(rgd.log.getEffectiveLevel()) == "DEBUG"
    assert (
        logging.getLevelName(logging.getLogger("test").getEffectiveLevel()) == "WARNING"
    )
    assert rgd.debug_set_expiry == 5 + 300
    assert rgd.key_prefix == "default_namespace"
    assert rgd.psubscribe == "__keyevent@0__:expired"


def test_redis_get_debugger_factory_invalid_loglevel_raises():
    redis_client = MagicMock()
    with pytest.raises(ValueError):
        RedisGetDebuggerFactory(redis_client, "invalid", 5, "default_namespace")
