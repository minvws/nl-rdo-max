from typing import Optional

from redis import StrictRedis

from ..config import Settings, get_settings


def create_redis_client(settings: Optional[Settings] = None) -> StrictRedis:
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
    settings = settings if settings is not None else get_settings()
    use_ssl = settings.redis.ssl

    if use_ssl:
        return StrictRedis(
            host=settings.redis.host,
            port=settings.redis.port,
            db=0,
            ssl=True,
            ssl_keyfile=settings.redis.key,
            ssl_certfile=settings.redis.cert,
            ssl_ca_certs=settings.redis.cafile,
        )

    return StrictRedis(host=settings.redis.host, port=settings.redis.port, db=0)
