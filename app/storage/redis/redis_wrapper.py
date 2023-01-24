from typing import Union
from pyop.storage import RedisWrapper as PRW

try:
    from redis.client import Redis
except ImportError:
    _HAS_REDIS = False
else:
    _HAS_REDIS = True


class RedisWrapper(PRW):
    """
    Child class of Pyop RedisWrapper allowing to re-use a redis client. Which is not possible in the current
    class.
    """

    # pylint: disable=super-init-not-called, dangerous-default-value
    def __init__(
        self, redis_client: Redis, collection: str, ttl: Union[int, None] = None
    ):
        if not _HAS_REDIS:
            raise ImportError("redis module is required but it is not available")

        self._db = redis_client
        self._collection = collection
        if ttl is None or (isinstance(ttl, int) and ttl >= 0):
            self._ttl = ttl
        else:
            raise ValueError("TTL must be a non-negative integer or None")
