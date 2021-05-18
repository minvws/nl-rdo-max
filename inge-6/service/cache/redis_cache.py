import redis

from ...config import settings

class RedisCache:
    EXPIRES_IN_MS = 60000 * 15

    def __init__(self):
        self.redis_client = redis.Redis(host=settings.redis_host, port=settings.redis_port, db=0)

    def set(self, name: str, value: str):
        self.redis_client.set(name, value, ex= self.EXPIRES_IN_MS)

    def get(self, name):
        self.redis_client.get(name)

    def gen_token(self):
        return self.redis_client.acl_genpass()

redis_cache_service =  RedisCache()