import uuid
from unittest.mock import MagicMock, patch

from app.storage.redis.redis_cache import RedisCache

namespace = str(uuid.uuid4())
key = str(uuid.uuid4())
value = str(uuid.uuid4()).encode("utf-8")


def create_redis_cache(
        redis_client=MagicMock(),
        redis_get_debugger_factory=MagicMock(),
        redis_get_debugger=MagicMock(),
        enable_debugger=False,
        expire_in_seconds=53
):
    redis_get_debugger_factory.create.return_value = redis_get_debugger
    return RedisCache(namespace, enable_debugger, expire_in_seconds, redis_client, redis_get_debugger_factory)


def test_setup_redis_debugger():
    redis_get_debugger_factory = MagicMock()
    redis_get_debugger = MagicMock()
    create_redis_cache(
        redis_get_debugger=redis_get_debugger,
        redis_get_debugger_factory=redis_get_debugger_factory,
        enable_debugger=True
    )

    redis_get_debugger_factory.create.assert_called_with(daemon=True)
    redis_get_debugger.start.assert_called()
    redis_get_debugger.run.assert_not_called()


def test_get():
    redis_client = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
    )
    redis_client.get.return_value = value

    actual = cache.get(key)
    assert actual == value
    redis_client.get.assert_called_with(f"{namespace}:{key}")


def test_get_with_debug_enabled():
    redis_client = MagicMock()
    redis_debugger = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
        enable_debugger=True,
        redis_get_debugger=redis_debugger
    )
    redis_client.get.return_value = value
    redis_client.exists.return_value = 0

    actual = cache.get(key)
    assert actual == value
    redis_client.get.assert_called_with(f"{namespace}:DEBUG:{key}")
    redis_client.exists.assert_called_with(f"{namespace}:{key}")
    redis_debugger.debug_get.assert_called_with(f"{namespace}:DEBUG:{key}", value)


def test_get_with_debug_enabled_and_key_already_exists():
    redis_client = MagicMock()
    redis_debugger = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
        enable_debugger=True,
        redis_get_debugger=redis_debugger
    )
    redis_client.get.return_value = value
    redis_client.exists.return_value = 1

    actual = cache.get(key)
    assert actual == value
    redis_client.get.assert_called_with(f"{namespace}:{key}")
    redis_client.exists.assert_called_with(f"{namespace}:{key}")
    redis_debugger.debug_get.assert_called_with(f"{namespace}:{key}", value)


def test_get_int():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    value = b'5'
    expected = 5
    with patch.object(RedisCache, 'get', return_value=value) as get_method:
        actual = cache.get_int(key)
        assert actual == expected
        get_method.assert_called_with(key)


def test_get_int_when_not_parsable_returns_none():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    with patch.object(RedisCache, 'get', return_value=value) as get_method:
        actual = cache.get_int(key)
        assert actual is None
        get_method.assert_called_with(key)


def test_get_string():
    cache = create_redis_cache()
    with patch.object(RedisCache, 'get', return_value=value) as get_method:
        actual = cache.get_string(key)
        assert actual == value.decode("utf-8")
        get_method.assert_called_with(key)


def test_get_bool_non_true_returns_false():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    with patch.object(RedisCache, 'get', return_value=value) as get_method:
        actual = cache.get_bool(key)
        assert actual is False
        get_method.assert_called_with(key)


def test_get_bool_from_string():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    value = b"TruE"
    with patch.object(RedisCache, 'get', return_value=value) as get_method:
        actual = cache.get_bool(key)
        assert actual is True
        get_method.assert_called_with(key)


def test_get_bool_from_int():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    value = b"1"
    with patch.object(RedisCache, 'get', return_value=value) as get_method:
        actual = cache.get_bool(key)
        assert actual is True
        get_method.assert_called_with(key)


def test_set():
    redis_client = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
        expire_in_seconds=4
    )
    redis_client.set.side_effect = [True, False]

    assert cache.set(key, value) is True
    redis_client.set.assert_called_with(f"{namespace}:{key}", value, ex=4)
    assert cache.set(key, value) is False


def test_set_complex_object(mocker):
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    value = {"bla": "complex"}
    serialized = b'pickle_output'
    pickle_patch = mocker.patch("pickle.dumps")
    pickle_patch.return_value = serialized
    with patch.object(RedisCache, 'set', side_effect=[True, False]) as set_method:
        actual = cache.set_complex_object(key, value)
        assert actual is True
        set_method.assert_called_with(key, serialized)
        pickle_patch.assert_called_with(value)
        assert cache.set_complex_object(key, value) is False


def test_get_complex_object(mocker):
    cache = create_redis_cache()
    deserialized = {"bla": "complex"}
    # noinspection PyShadowingNames
    value = b'serialized'
    pickle_patch = mocker.patch("pickle.loads")
    pickle_patch.return_value = deserialized
    with patch.object(RedisCache, 'get', side_effect=[value,None]) as get_method:
        actual = cache.get_complex_object(key)
        assert actual == deserialized
        get_method.assert_called_with(key)
        pickle_patch.assert_called_with(value)
        assert cache.get_complex_object(key) is None


def test_gen_token():
    redis_client = MagicMock()
    expected = "truerandom"
    redis_client.acl_genpass.return_value = expected
    cache = create_redis_cache(redis_client=redis_client)
    actual = cache.gen_token()
    assert actual == expected


def test_incr():
    redis_client = MagicMock()
    expected = "5"
    redis_client.incr.return_value = expected
    cache = create_redis_cache(redis_client=redis_client)
    actual = cache.incr(key)
    assert actual == expected
    redis_client.incr.assert_called_with(f"{namespace}:{key}")


def test_expire():
    redis_client = MagicMock()
    cache = create_redis_cache(redis_client=redis_client)
    cache.expire(key, 5434)
    redis_client.expire.assert_called_with(f"{namespace}:{key}", 5434, nx=True)


def test_delete():
    redis_client = MagicMock()
    cache = create_redis_cache(redis_client=redis_client)
    cache.delete(key)
    redis_client.delete.assert_called_with(f"{namespace}:{key}")


def test_prepend_with_namespace_when_debug_enabled():
    redis_client = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
        enable_debugger=True
    )
    redis_client.exists.return_value = 0
    expected = f"{namespace}:DEBUG:{key}"
    actual = cache._prepend_with_namespace(key)
    assert actual == expected
    redis_client.exists.assert_called_with(f"{namespace}:{key}")


def test_prepend_with_namespace_when_debug_enabled_end_non_debug_key_already_exists():
    redis_client = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
        enable_debugger=True
    )
    redis_client.exists.return_value = 1
    expected = f"{namespace}:{key}"
    actual = cache._prepend_with_namespace(key)
    assert actual == expected
    redis_client.exists.assert_called_with(f"{namespace}:{key}")


def test_prepend_with_namespace_when_debug_not_enabled():
    redis_client = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
        enable_debugger=False
    )
    expected = f"{namespace}:{key}"
    actual = cache._prepend_with_namespace(key)
    assert actual == expected
    redis_client.exists.assert_not_called()
