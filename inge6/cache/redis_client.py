from typing import Optional

from redis import StrictRedis

from .redis_debugger import RedisGetDebugger
from ..config import get_settings

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
        use_ssl = get_settings().redis.ssl

        if use_ssl:
            _REDIS_CLIENT = StrictRedis(
                                host=get_settings().redis.host, port=get_settings().redis.port, db=0,
                                ssl=True,
                                ssl_keyfile=get_settings().redis.key, ssl_certfile=get_settings().redis.cert,
                                ssl_ca_certs=get_settings().redis.cafile
                            )
        else:
            _REDIS_CLIENT = StrictRedis(host=get_settings().redis.host, port=get_settings().redis.port, db=0)

        if get_settings().redis.enable_debugger:
            log_expiration_events_thread = RedisGetDebugger(_REDIS_CLIENT, daemon=True)
            log_expiration_events_thread.start()

    return _REDIS_CLIENT
