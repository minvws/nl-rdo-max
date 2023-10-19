import uuid
from typing import Dict
from unittest.mock import MagicMock, patch

from app.storage.redis.redis_cache import RedisCache

A_NAMESPACE = str(uuid.uuid4())
A_KEY = str(uuid.uuid4())
A_VALUE = str(uuid.uuid4()).encode("utf-8")


def create_redis_cache(
    redis_client=MagicMock(),
    redis_get_debugger_factory=MagicMock(),
    redis_get_debugger=MagicMock(),
    enable_debugger=False,
    expire_in_seconds=53,
):
    redis_get_debugger_factory.create.return_value = redis_get_debugger
    return RedisCache(
        A_NAMESPACE,
        enable_debugger,
        expire_in_seconds,
        redis_client,
        redis_get_debugger_factory,
    )


def test_setup_redis_debugger():
    redis_get_debugger_factory = MagicMock()
    redis_get_debugger = MagicMock()
    create_redis_cache(
        redis_get_debugger=redis_get_debugger,
        redis_get_debugger_factory=redis_get_debugger_factory,
        enable_debugger=True,
    )

    redis_get_debugger_factory.create.assert_called_with(daemon=True)
    redis_get_debugger.start.assert_called()
    redis_get_debugger.run.assert_not_called()


def test_get():
    redis_client = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
    )
    redis_client.get.return_value = A_VALUE

    actual = cache.get(A_KEY)
    assert actual == A_VALUE
    redis_client.get.assert_called_with(f"{A_NAMESPACE}:{A_KEY}")


def test_get_with_debug_enabled():
    redis_client = MagicMock()
    redis_debugger = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
        enable_debugger=True,
        redis_get_debugger=redis_debugger,
    )
    redis_client.get.return_value = A_VALUE
    redis_client.exists.return_value = 0

    actual = cache.get(A_KEY)
    assert actual == A_VALUE
    redis_client.get.assert_called_with(f"{A_NAMESPACE}:DEBUG:{A_KEY}")
    redis_client.exists.assert_called_with(f"{A_NAMESPACE}:{A_KEY}")
    redis_debugger.debug_get.assert_called_with(f"{A_NAMESPACE}:DEBUG:{A_KEY}", A_VALUE)


def test_get_with_debug_enabled_and_key_already_exists():
    redis_client = MagicMock()
    redis_debugger = MagicMock()
    cache = create_redis_cache(
        redis_client=redis_client,
        enable_debugger=True,
        redis_get_debugger=redis_debugger,
    )
    redis_client.get.return_value = A_VALUE
    redis_client.exists.return_value = 1

    actual = cache.get(A_KEY)
    assert actual == A_VALUE
    redis_client.get.assert_called_with(f"{A_NAMESPACE}:{A_KEY}")
    redis_client.exists.assert_called_with(f"{A_NAMESPACE}:{A_KEY}")
    redis_debugger.debug_get.assert_called_with(f"{A_NAMESPACE}:{A_KEY}", A_VALUE)


def test_get_int():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    # pylint:disable=redefined-outer-name
    value = b"5"
    expected = 5
    with patch.object(RedisCache, "get", return_value=value) as get_method:
        actual = cache.get_int(A_KEY)
        assert actual == expected
        get_method.assert_called_with(A_KEY)


def test_get_int_when_not_parsable_returns_none():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    # pylint:disable=redefined-outer-name
    with patch.object(RedisCache, "get", return_value=A_VALUE) as get_method:
        actual = cache.get_int(A_KEY)
        assert actual is None
        get_method.assert_called_with(A_KEY)


def test_get_string():
    cache = create_redis_cache()
    with patch.object(RedisCache, "get", return_value=A_VALUE) as get_method:
        actual = cache.get_string(A_KEY)
        assert actual == A_VALUE.decode("utf-8")
        get_method.assert_called_with(A_KEY)


def test_get_bool_non_true_returns_false():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    with patch.object(RedisCache, "get", return_value=A_VALUE) as get_method:
        actual = cache.get_bool(A_KEY)
        assert actual is False
        get_method.assert_called_with(A_KEY)


def test_get_bool_from_string():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    # pylint:disable=redefined-outer-name
    value = b"TruE"
    with patch.object(RedisCache, "get", return_value=value) as get_method:
        actual = cache.get_bool(A_KEY)
        assert actual is True
        get_method.assert_called_with(A_KEY)


def test_get_bool_from_int():
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    # pylint:disable=redefined-outer-name
    value = b"1"
    with patch.object(RedisCache, "get", return_value=value) as get_method:
        actual = cache.get_bool(A_KEY)
        assert actual is True
        get_method.assert_called_with(A_KEY)


def test_set():
    redis_client = MagicMock()
    cache = create_redis_cache(redis_client=redis_client, expire_in_seconds=4)
    redis_client.set.side_effect = [True, False]

    assert cache.set(A_KEY, A_VALUE) is True
    redis_client.set.assert_called_with(f"{A_NAMESPACE}:{A_KEY}", A_VALUE, ex=4)
    assert cache.set(A_KEY, A_VALUE) is False


class SerializationTestObject:
    def __init__(self, key: str):
        self.key = key

    def to_dict(self):
        return {"key": self.key}

    @classmethod
    def from_dict(cls, dictionary: Dict[str, str]):
        return cls(dictionary["key"])


def test_set_complex_object(mocker):
    cache = create_redis_cache()
    # noinspection PyShadowingNames
    # pylint:disable=redefined-outer-name
    value = SerializationTestObject("value")
    serialized = b'{"key": "value"}'
    with patch.object(RedisCache, "set", side_effect=[True, False]) as set_method:
        actual = cache.set_complex_object(A_KEY, value)
        assert actual is True
        set_method.assert_called_with(A_KEY, serialized)
        assert cache.set_complex_object(A_KEY, value) is False


def test_get_complex_object(mocker):
    cache = create_redis_cache()
    deserialized = SerializationTestObject("value")
    # noinspection PyShadowingNames
    # pylint:disable=redefined-outer-name
    value = b'{"key": "value"}'
    with patch.object(RedisCache, "get", side_effect=[value, None]) as get_method:
        actual = cache.get_complex_object(A_KEY, SerializationTestObject)
        assert actual.key == deserialized.key
        get_method.assert_called_with(A_KEY)
        assert cache.get_complex_object(A_KEY, SerializationTestObject) is None


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
    actual = cache.incr(A_KEY)
    assert actual == expected
    redis_client.incr.assert_called_with(f"{A_NAMESPACE}:{A_KEY}")


def test_expire():
    redis_client = MagicMock()
    cache = create_redis_cache(redis_client=redis_client)
    cache.expire(A_KEY, 5434)
    redis_client.expire.assert_called_with(f"{A_NAMESPACE}:{A_KEY}", 5434)


def test_delete():
    redis_client = MagicMock()
    cache = create_redis_cache(redis_client=redis_client)
    cache.delete(A_KEY)
    redis_client.delete.assert_called_with(f"{A_NAMESPACE}:{A_KEY}")


def test_prepend_with_namespace_when_debug_enabled():
    redis_client = MagicMock()
    cache = create_redis_cache(redis_client=redis_client, enable_debugger=True)
    redis_client.exists.return_value = 0
    expected = f"{A_NAMESPACE}:DEBUG:{A_KEY}"
    # pylint:disable=protected-access
    actual = cache._prepend_with_namespace(A_KEY)
    assert actual == expected
    redis_client.exists.assert_called_with(f"{A_NAMESPACE}:{A_KEY}")


def test_prepend_with_namespace_when_debug_enabled_end_non_debug_key_already_exists():
    redis_client = MagicMock()
    cache = create_redis_cache(redis_client=redis_client, enable_debugger=True)
    redis_client.exists.return_value = 1
    expected = f"{A_NAMESPACE}:{A_KEY}"
    # pylint:disable=protected-access
    actual = cache._prepend_with_namespace(A_KEY)
    assert actual == expected
    redis_client.exists.assert_called_with(f"{A_NAMESPACE}:{A_KEY}")


def test_prepend_with_namespace_when_debug_not_enabled():
    redis_client = MagicMock()
    cache = create_redis_cache(redis_client=redis_client, enable_debugger=False)
    expected = f"{A_NAMESPACE}:{A_KEY}"
    # pylint:disable=protected-access
    actual = cache._prepend_with_namespace(A_KEY)
    assert actual == expected
    redis_client.exists.assert_not_called()
