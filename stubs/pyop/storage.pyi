from abc import ABC
from typing import Union
from redis import Redis

class StorageBase(ABC): ...

class RedisWrapper(StorageBase):
    def __init__(
        self,
        collection: str,
        db_uri: str = ...,
        redis: Redis = ...,
        ttl: Union[int, None] = None,
        extra_options: dict = {},
    ) -> None: ...
