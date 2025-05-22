"""

Module contains all the commands regarding redis caching. Prepending prefixes, and defining Time To Live.

Required settings:
    - settings.redis.default_cache_namespace, prefix all redis cache keys.
    - settings.redis.object_ttl, time to live for all objects stored in cache
"""

import json
from typing import Any, Optional, Union, Type

from redis import Redis

from app.storage.cache import Cache
from .redis_debugger import RedisGetDebuggerFactory


def _serialize(value: Any) -> bytes:
    """
    Function that specifies how the data should be serialized into the redis-server.

    :param value: Any value that should be storen in a redis database
    :returns: Serialized value, a json dump.
    """
    if hasattr(value, "to_dict") and callable(getattr(value, "to_dict")):
        return json.dumps(value.to_dict()).encode("utf-8")
    raise NotImplementedError("to_dict not implemented")


def _deserialize(serialized_value: Optional[Any], clazz: Type) -> Any:
    """
    Specifies the opposite of the serialize function, expects the output of a redis GET command. And
    returns the deserialized version of that output.

    :param serialized_value: value retrieved from our redis-server connection
    :returns: deserialized version of the object stored in redis.
    """
    if not serialized_value:
        return None
    if hasattr(clazz, "from_dict") and callable(getattr(clazz, "from_dict")):
        return clazz.from_dict(json.loads(serialized_value.decode("utf-8")))
    raise NotImplementedError("from_dict not implemented")


class RedisCache(Cache):
    def __init__(
        self,
        default_cache_namespace: str,
        enable_debugger,
        expires_in_seconds: int,
        redis_client: Redis,
        redis_get_debugger_factory: RedisGetDebuggerFactory,
    ):
        self.key_prefix: str = default_cache_namespace
        self.expires_in_s: int = expires_in_seconds
        self.enable_debugger = enable_debugger
        self.redis_client = redis_client

        if self.enable_debugger:
            self.redis_debugger = redis_get_debugger_factory.create(daemon=True)
            self.redis_debugger.start()

    def get(self, key: str) -> Any:
        key_with_namespace = self._prepend_with_namespace(key)
        ret_value = self.redis_client.get(key_with_namespace)
        if self.enable_debugger:
            self.redis_debugger.debug_get(key_with_namespace, ret_value)
        return ret_value

    def get_and_delete(self, key: str) -> Any:
        key_with_namespace = self._prepend_with_namespace(key)
        ret_value = self.redis_client.getdel(key_with_namespace)
        if self.enable_debugger:
            self.redis_debugger.debug_get(key_with_namespace, ret_value)
        return ret_value

    def get_int(self, key: str) -> Optional[int]:
        i_int = self.get(key)
        if isinstance(i_int, bytes):
            try:
                return int(i_int.decode("utf-8"))
            except ValueError as _:
                pass
        return None

    def get_string(self, key: str) -> Optional[str]:
        s_string = self.get(key)
        if isinstance(s_string, bytes):
            return s_string.decode("utf-8")
        return None

    def get_bool(self, key: str) -> bool:
        b_byte = self.get(key)
        if b_byte is not None:
            b_byte_lower = b_byte.decode("utf-8").lower()
            return b_byte_lower in ("1", "true")
        return False

    def set(self, key: str, value: Any) -> Union[bool, None]:
        return self.redis_client.set(
            self._prepend_with_namespace(key), value, ex=self.expires_in_s
        )

    def set_complex_object(self, key: str, value: Any) -> Union[bool, None]:
        return self.set(key, _serialize(value))

    def get_complex_object(self, key: str, clazz: Type) -> Any:
        return _deserialize(self.get(key), clazz)

    def get_and_delete_complex_object(self, key: str, clazz: Type) -> Any:
        return _deserialize(self.get_and_delete(key), clazz)

    def gen_token(self) -> str:
        """
        Generate a random string, useful to generate unique keys that should be stored in the redis database.
        """
        return self.redis_client.acl_genpass()

    def incr(self, key):
        """
        Increases the value of a key
        """
        key = self._prepend_with_namespace(key)
        return self.redis_client.incr(key)

    def expire(self, key, time_in_seconds):
        """
        Expires the value of a key
        """
        key = self._prepend_with_namespace(key)
        self.redis_client.expire(key, time_in_seconds)

    def delete(self, key):
        """
        Deletes the value of the key
        """
        key = self._prepend_with_namespace(key)
        self.redis_client.delete(key)

    def ping(self):
        """
        Pings the Redis Server
        """
        return self.redis_client.ping()

    def _prepend_with_namespace(self, key: str) -> str:
        namespace_key = f"{self.key_prefix}:{key}"
        if self.enable_debugger and not self.redis_client.exists(namespace_key) > 0:
            return f"{self.key_prefix}:DEBUG:{key}"
        return namespace_key
