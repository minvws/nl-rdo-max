from os import name
from typing import Any
import pickle

from redis import Redis

from . import get_redis_client
from ..config import settings

NOT_SERIALIZE_TYPES = (int, str, bytes, dict, list)

KEY_PREFIX = 'TVS:'
EXPIRES_IN_S = int(settings.redis.expires_in_s)

def _serialize(value):
    return pickle.dumps(value)
    if not isinstance(value, NOT_SERIALIZE_TYPES):
        return pickle.dumps(value)
    return value

def _deserialize(serialized_value):
    return pickle.loads(serialized_value) if serialized_value else None
    if not isinstance(serialized_value, NOT_SERIALIZE_TYPES):
        return pickle.loads(serialized_value) if serialized_value else None
    return serialized_value

def _get_namespace(namespace):
    return KEY_PREFIX + namespace

def set(key: str, value: Any):
    key = _get_namespace(key)
    serialized_value = _serialize(value)
    get_redis_client().set(key, serialized_value, ex=EXPIRES_IN_S)

def get(key: str):
    key = _get_namespace(key)
    value = get_redis_client().get(key)
    deserialized_value = _deserialize(value)
    return deserialized_value

def hset(namespace: str, key: str, value: Any):
    serialized_value = _serialize(value)
    namespace = _get_namespace(namespace)
    get_redis_client().hset(namespace, key, serialized_value)
    get_redis_client().expire(name=namespace, time=EXPIRES_IN_S)

def hget(namespace, key):
    namespace = _get_namespace(namespace)
    value = get_redis_client().hget(namespace, key)
    deserialized_value = _deserialize(value)
    return deserialized_value

def delete(namespace, key):
    # TODO
    pass

def gen_token():
    return get_redis_client().acl_genpass()
