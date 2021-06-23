# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
from typing import Any, Text, Optional
import pickle

from . import get_redis_client
from ..config import settings

KEY_PREFIX: str = settings.redis.default_cache_namespace
EXPIRES_IN_S: int = int(settings.redis.object_ttl)

def _serialize(value: Any) -> bytes:
    """
    Function that specifies how the data should be serialized into the redis-server.

    :param value: Any value that should be storen in a redis database
    :returns: Serialized value, a pickle dump.
    """
    return pickle.dumps(value)

def _deserialize(serialized_value: Optional[Any]) -> Any:
    """
    Specifies the opposite of the serialize function, expects the output of a redis GET command. And
    returns the deserialized version of that output.

    :param serialized_value: value retrieved from our redis-server connection
    :returns: deserialized version of the object stored in redis.
    """
    return pickle.loads(serialized_value) if serialized_value else None

def _get_namespace(namespace: str) -> str:
    """
    As the server connecting to might be used by other clients, we need to specify a namespace for our keys. Such that
    there is no conflict of keys possible.

    :param namespace: The key that needs to be prefixed
    :returns: the namespaces key.
    """
    return KEY_PREFIX + namespace

# pylint: disable=redefined-builtin
def set(key: str, value: Any) -> None:
    """
    Store a value in the redis database using the specified key.

    :param key: key used to link with the value
    :param value: value we want to store
    """
    key = _get_namespace(key)
    serialized_value = _serialize(value)
    get_redis_client().set(key, serialized_value, ex=EXPIRES_IN_S)

# pylint: disable=redefined-builtin
def get(key: str) -> Any:
    """
    Retrieve a value from the redis database using the specified key

    :param key: used to retrieve the stored value

    :returns: the value belonging to the specified key
    """
    key = _get_namespace(key)
    value = get_redis_client().get(key)
    deserialized_value = _deserialize(value)
    return deserialized_value

def hset(namespace: str, key: str, value: Any) -> None:
    """
    Set a value in the redis database within a namespace. Rather than manually
    prefixing the key, use the internal redis namespace system
    to store keys without clashing with other clients.

    :param namespace: the namespace redis should use internally
    :param key: the key to store with your value
    :param value: the value to store in the redis database
    """
    serialized_value = _serialize(value)
    namespace = _get_namespace(namespace)
    get_redis_client().hset(namespace, key, serialized_value)
    get_redis_client().expire(name=namespace, time=EXPIRES_IN_S)

def hget(namespace, key) -> Any:
    """
    Get a value from the redis database within a namespace. Rather than
    manually prefixing the key, use the internal redis namespace system
    to retrieve keys without clashing with other clients.
    """
    namespace = _get_namespace(namespace)
    value = get_redis_client().hget(namespace, key)
    deserialized_value = _deserialize(value)
    return deserialized_value

def gen_token() -> Text:
    """
    Generate a random string, useful to generate unique keys that should be stored in the redis database.
    """
    return get_redis_client().acl_genpass()
