from unittest.mock import MagicMock

import pytest

from app.storage.redis.redis_wrapper import RedisWrapper


def test_redis_wrapper_negative_ttl_should_raise_exception():
    with pytest.raises(ValueError):
        RedisWrapper(redis_client=MagicMock(), collection="collection_name", ttl=-1)
    RedisWrapper(redis_client=MagicMock(), collection="collection_name", ttl=None)
    RedisWrapper(redis_client=MagicMock(), collection="collection_name", ttl=0)
    RedisWrapper(redis_client=MagicMock(), collection="collection_name", ttl=5)
