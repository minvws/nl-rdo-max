from redis import StrictRedis


def create_redis_client(redis_settings) -> StrictRedis:
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
    use_ssl = redis_settings["ssl"] == "True"
    if use_ssl:
        return StrictRedis(
            host=redis_settings["host"],
            port=redis_settings["port"],
            db=0,
            ssl=True,
            ssl_keyfile=redis_settings["key"],
            ssl_certfile=redis_settings["cert"],
            ssl_ca_certs=redis_settings["cafile"],
        )

    return StrictRedis(host=redis_settings["host"], port=redis_settings["port"], db=0)
