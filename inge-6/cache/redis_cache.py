from typing import Any
import pickle

from redis import Redis

from ..config import settings

class RedisCache:
    KEY_PREFIX = 'TVS-'
    EXPIRES_IN_S = 60 * 15

    def __init__(self):
        self.redis_client = Redis(host=settings.redis.host, port=settings.redis.port, db=0)

    def set(self, name: str, value: Any):
        serialized_value = pickle.dumps(value)
        self.redis_client.set(self.KEY_PREFIX + name, serialized_value, ex=self.EXPIRES_IN_S)

    def get(self, name):
        serialized_value = self.redis_client.get(self.KEY_PREFIX + name)
        return pickle.loads(serialized_value) if serialized_value else None

    def gen_token(self):
        return self.redis_client.acl_genpass()

redis_cache_service =  RedisCache()