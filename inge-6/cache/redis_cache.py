from typing import Any
import pickle

from redis import Redis

from . import get_redis_client
from ..config import settings

class RedisCache:
    KEY_PREFIX = 'TVS:'
    EXPIRES_IN_S = 60 * 15

    def set(self, name: str, value: Any):
        serialized_value = pickle.dumps(value)
        get_redis_client().set(self.KEY_PREFIX + name, serialized_value, ex=self.EXPIRES_IN_S)

    def get(self, name):
        serialized_value = get_redis_client().get(self.KEY_PREFIX + name)
        return pickle.loads(serialized_value) if serialized_value else None

    def delete(self, name):
        get_redis_client().delete(self.KEY_PREFIX + name)

    def gen_token(self):
        return get_redis_client().acl_genpass()

redis_cache_service =  RedisCache()