from typing import Any, Text, Optional
import pickle

from . import get_redis_client
from ..config import settings

KEY_PREFIX: str = settings.redis.default_cache_namespace
EXPIRES_IN_S: int = int(settings.redis.object_ttl)

def _serialize(value: Any) -> bytes:
    return pickle.dumps(value)

def _deserialize(serialized_value: Optional[Any]) -> Any:
    return pickle.loads(serialized_value) if serialized_value else None

def _get_namespace(namespace: str) -> str:
    return KEY_PREFIX + namespace

# pylint: disable=redefined-builtin
def set(key: str, value: Any) -> None:
    key = _get_namespace(key)
    serialized_value = _serialize(value)
    get_redis_client().set(key, serialized_value, ex=EXPIRES_IN_S)

# pylint: disable=redefined-builtin
def get(key: str) -> Any:
    key = _get_namespace(key)
    value = get_redis_client().get(key)
    deserialized_value = _deserialize(value)
    return deserialized_value

def hset(namespace: str, key: str, value: Any) -> None:
    serialized_value = _serialize(value)
    namespace = _get_namespace(namespace)
    get_redis_client().hset(namespace, key, serialized_value)
    get_redis_client().expire(name=namespace, time=EXPIRES_IN_S)

def hget(namespace, key) -> Any:
    namespace = _get_namespace(namespace)
    value = get_redis_client().hget(namespace, key)
    deserialized_value = _deserialize(value)
    return deserialized_value

def delete(namespace, key) -> None:
    key = _get_namespace(namespace + key)
    get_redis_client().delete(key)

def gen_token() -> Text:
    return get_redis_client().acl_genpass()
