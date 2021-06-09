from typing import Optional

from redis import StrictRedis
from ..config import settings

# pylint: disable=global-statement
_REDIS_CLIENT: Optional[StrictRedis] = None

def get_redis_client() -> StrictRedis:
    global _REDIS_CLIENT
    if _REDIS_CLIENT is None:
        _REDIS_CLIENT = StrictRedis(host=settings.redis.host, port=settings.redis.port, db=0)

    return _REDIS_CLIENT
