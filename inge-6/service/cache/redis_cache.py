import redis

class RedisCache:
    EXPIRES_IN_MS = 60000 * 15

    def __init__(self):
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)

    def set(self, name: str, value: str):
        self.redis_client.set(name, value, ex= self.EXPIRES_IN_MS)

    def get(self, name):
        self.redis_client.get(name)

    def gen_token(self):
        return self.redis_client.acl_genpass()
