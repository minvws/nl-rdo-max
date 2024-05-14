from unittest.mock import MagicMock, patch

from app.storage.redis.redis_debugger import RedisGetDebugger


def test_debug_get_called_with_none_value(mocker):
    log = MagicMock()
    mocker.patch("logging.getLogger", return_value=log)
    redis_client = MagicMock()
    rgd = RedisGetDebugger(redis_client, 10, 5, "debug_namespace")
    rgd.debug_get("key", None)
    log.debug.assert_called_with("Retrieved expired value with key: %s", "key")


def test_debug_get(mocker):
    log = MagicMock()
    mocker.patch("logging.getLogger", return_value=log)
    redis_client = MagicMock()
    rgd = RedisGetDebugger(redis_client, 10, 5, "debug_namespace")
    rgd.debug_get("key", "value")
    log.debug.assert_not_called()
    redis_client.set.assert_called_with(
        "debug_namespace:retrieved:key", "value", ex=305
    )


def test_run_should_call_listen_for_expiration_events():
    redis_client = MagicMock()
    rgd = RedisGetDebugger(redis_client, 10, 5, "debug_namespace")
    with patch.object(
        RedisGetDebugger, "_listen_for_expiration_events"
    ) as listen_method:
        rgd.run()
        listen_method.assert_called()
