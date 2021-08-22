from datetime import datetime

from .exceptions import TooManyRequestsFromOrigin, TooBusyError, ExpectedRedisValue
from .cache import get_redis_client
from .config import settings


def _ip_limit_test(ip_address: str, ip_expire_s: int) -> None:
    ip_key = "tvs:ipv4:" + ip_address
    ip_key_exists = get_redis_client().incr(ip_key)
    if ip_key_exists != 1:
        raise TooManyRequestsFromOrigin(f"Too many requests from the same ip_address during the last {ip_expire_s} seconds.")
    get_redis_client().expire(ip_key, ip_expire_s)


def _user_limit_test(idp_prefix: str, user_limit_key: str) -> None:
    user_limit = get_redis_client().get(user_limit_key)

    if user_limit is None:
        return

    user_limit = int(user_limit)
    timeslot = int(datetime.utcnow().timestamp())

    timeslot_key = "tvs:limiter:{}:{}".format(idp_prefix.upper(), str(timeslot))
    num_users = get_redis_client().incr(timeslot_key)

    if num_users == 1:
        get_redis_client().expire(timeslot_key, 2)
    elif num_users >= user_limit:
        raise TooBusyError("Servers are too busy at this point, please try again later")


def rate_limit_test(ip_address: str) -> str:
    """
    Test is we have passed the user limit defined in the redis-store. The rate limit
    defines the number of users per second which we allow.

    if no user_limit is found in the redis store, this check is treated as 'disabled'.

    :param user_limit_key: the key in the redis store that defines the number of allowed users per 10th of a second
    :raises: TooBusyError when the number of users exceeds the allowed number.
    """
    _ip_limit_test(ip_address=ip_address, ip_expire_s=int(settings.ratelimit.ip_expire_in_s))

    connect_to_idp = get_redis_client().get(settings.connect_to_idp_key)
    if connect_to_idp is not None:
        connect_to_idp = connect_to_idp.decode()
    else:
        raise ExpectedRedisValue("Expected {} key to be set in redis.".format(settings.connect_to_idp_key))

    overflow_idp = get_redis_client().get(settings.overflow_idp_key)

    if overflow_idp and overflow_idp.decode().lower() != 'false':
        overflow_idp = overflow_idp.decode()
        try:
            _user_limit_test(idp_prefix=connect_to_idp, user_limit_key=settings.ratelimit.user_limit_key)
            return connect_to_idp
        except TooBusyError:
            _user_limit_test(idp_prefix=overflow_idp, user_limit_key=settings.ratelimit.user_limit_key)
            return overflow_idp
    else:
        _user_limit_test(idp_prefix=connect_to_idp, user_limit_key=settings.ratelimit.user_limit_key)
        return connect_to_idp
