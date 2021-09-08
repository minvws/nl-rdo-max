from typing import Optional
import logging

from redis import StrictRedis
from ..config import settings
from .redis_debugger import RedisGetDebugger

# pylint: disable=global-statement
_REDIS_CLIENT: Optional[StrictRedis] = None

def get_redis_client() -> StrictRedis:
    """
    Global function to retrieve the connection with the redis-server.

    Required settings:
        - settings.redis.host
        - settings.redis.port

    Optional settings:
        - settings.redis.key, path to the private key
        - settings.redis.cert, path to the certificate
        - settings.redis.cafile, path to a CAFile

    :returns: StrictRedis object having a connection with the configured redis server.
    """
    global _REDIS_CLIENT
    if _REDIS_CLIENT is None:
        use_ssl = settings.redis.ssl.lower() == 'true'

        if use_ssl:
            _REDIS_CLIENT = StrictRedis(
                                host=settings.redis.host, port=settings.redis.port, db=0,
                                ssl=True,
                                ssl_keyfile=settings.redis.key, ssl_certfile=settings.redis.cert,
                                ssl_ca_certs=settings.redis.cafile
                            )
        else:
            _REDIS_CLIENT = StrictRedis(host=settings.redis.host, port=settings.redis.port, db=0)

        if settings.redis.enable_debugger:
            log_expiration_events_thread = RedisGetDebugger(_REDIS_CLIENT, daemon=True)
            log_expiration_events_thread.start()

    return _REDIS_CLIENT
