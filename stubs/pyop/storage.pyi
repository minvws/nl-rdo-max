from abc import ABC
from redis import Redis

class StorageBase(ABC):
    ...

class RedisWrapper(StorageBase):
    def __init__(self, collection: str, db_uri: str = ..., redis: Redis = ..., ttl: int = None) -> None: ...