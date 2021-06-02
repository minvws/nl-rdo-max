from os import name
from typing import Any
import pickle

from redis import Redis

from . import get_redis_client
from ..config import settings

NOT_SERIALIZE_TYPES = (int, str, bytes, dict, list)

class RedisCache:
    KEY_PREFIX = 'TVS:'
    EXPIRES_IN_S = int(settings.redis.expires_in_s)

    def __init__(self):
        # TODO: !!
        # get_redis_client().expire(settings.oidc.tvs_token_namespace, self.EXPIRES_IN_S)
        pass

    def _serialize(self, value):
        return pickle.dumps(value)
        if not isinstance(value, NOT_SERIALIZE_TYPES):
            return pickle.dumps(value)
        return value

    def _deserialize(self, serialized_value):
        return pickle.loads(serialized_value) if serialized_value else None
        if not isinstance(serialized_value, NOT_SERIALIZE_TYPES):
            return pickle.loads(serialized_value) if serialized_value else None
        return serialized_value

    def _get_namespace(self, namespace):
        return self.KEY_PREFIX + namespace

    def set(self, key: str, value: Any):
        key = self._get_namespace(key)
        serialized_value = self._serialize(value)
        get_redis_client().set(key, serialized_value, ex=self.EXPIRES_IN_S)

    def get(self, key: str):
        key = self._get_namespace(key)
        value = get_redis_client().get(key)
        deserialized_value = self._deserialize(value)
        return deserialized_value

    def hset(self, namespace: str, key: str, value: Any):
        serialized_value = self._serialize(value)
        namespace = self._get_namespace(namespace)
        get_redis_client().hset(namespace, key, serialized_value)
        get_redis_client().expire(name=namespace, time=self.EXPIRES_IN_S)

    def hget(self, namespace, key):
        namespace = self._get_namespace(namespace)
        value = get_redis_client().hget(namespace, key)
        deserialized_value = self._deserialize(value)
        return deserialized_value

    def delete(self, namespace, key):
        # TODO
        pass

    def gen_token(self):
        return get_redis_client().acl_genpass()

redis_cache_service =  RedisCache()