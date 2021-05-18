from typing import Any
import pickle

import redis

from ..config import settings

class RedisCache:
    EXPIRES_IN_S = 60 * 15

    def __init__(self):
        self.redis_client = redis.Redis(host=settings.redis_host, port=settings.redis_port, db=0)

    def set(self, name: str, value: Any):
        serialized_value = pickle.dumps(value)
        self.redis_client.set(name, serialized_value, ex=self.EXPIRES_IN_S)

    def get(self, name):
        serialized_value = self.redis_client.get(name)
        return pickle.loads(serialized_value) if serialized_value else None

    def gen_token(self):
        return self.redis_client.acl_genpass()

redis_cache_service =  RedisCache()