
from redis import StrictRedis
from ..config import settings

_REDIS_CLIENT = None

def get_redis_client():
    global _REDIS_CLIENT
    if _REDIS_CLIENT is None:
        _REDIS_CLIENT = StrictRedis(host=settings.redis.host, port=settings.redis.port, db=0)

    return _REDIS_CLIENT
