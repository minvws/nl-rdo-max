from typing import Any
import pickle

from . import get_redis_client
from ..config import settings

KEY_PREFIX = 'TVS:'
EXPIRES_IN_S = int(settings.redis.expires_in_s)

def _serialize(value):
    return pickle.dumps(value)

def _deserialize(serialized_value):
    return pickle.loads(serialized_value) if serialized_value else None

def _get_namespace(namespace):
    return KEY_PREFIX + namespace

# pylint: disable=redefined-builtin
def set(key: str, value: Any):
    key = _get_namespace(key)
    serialized_value = _serialize(value)
    get_redis_client().set(key, serialized_value, ex=EXPIRES_IN_S)

# pylint: disable=redefined-builtin
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
    get_redis_client().delete(namespace + key)

def gen_token():
    return get_redis_client().acl_genpass()
