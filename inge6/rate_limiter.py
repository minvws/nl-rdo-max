from datetime import datetime

from redis import StrictRedis

from .exceptions import TooManyRequestsFromOrigin, TooBusyError, ExpectedRedisValue
from .config import Settings


class RateLimiter:

    def __init__(self, settings: Settings, redis_client: StrictRedis):
        self.redis_client = redis_client
        self.settings = settings

    def ip_limit_test(self, ip_address: str, ip_expire_s: int, nof_attempts_s: int = 1) -> None:
        """
        Perform ip blocking. If the same IP-address accesses this service multiple times in
        `ip_expire_s` seconds, block the flow.

        :param ip_address: the ip address under consideration.
        :param ip_expire_s: every ip address is only allowed one request per configured number of seconds.
        """
        ip_key = "tvs:ipv4:" + ip_address
        ip_key_exists = self.redis_client.incr(ip_key)
        if ip_key_exists == 1:
            self.redis_client.expire(ip_key, ip_expire_s)

        if ip_key_exists > nof_attempts_s:
            raise TooManyRequestsFromOrigin(f"Too many requests from the same ip_address during the last {ip_expire_s} seconds.")


    def user_limit_test(self, idp_prefix: str, user_limit_key: str) -> None:
        """
        Test the user limit defined in redis under the user_limit_key, and tracking the current user load based on the used idp.

        :param idp_prefix: the prefix for tracking the user load.
        :param user_limit_key: the key in redis that has stored the user limit.
        """
        user_limit = self.redis_client.get(user_limit_key)

        if user_limit is None:
            return

        user_limit = int(user_limit)
        timeslot = int(datetime.utcnow().timestamp())

        timeslot_key = f"tvs:limiter:{idp_prefix.upper()}:{str(timeslot)}"
        num_users = self.redis_client.incr(timeslot_key)

        if num_users == 1:
            self.redis_client.expire(timeslot_key, 2)

        if num_users > user_limit:
            raise TooBusyError("Servers are too busy at this point, please try again later")


    def rate_limit_test(self, ip_address: str) -> str:
        """
        Tests if we have passed the user limit defined in the redis-store. The rate limit
        defines the number of users per second which we allow.

        if no user_limit is found in the redis store, this check is treated as 'disabled'.

        Required settings:
            - settings.ratelimit.ip_expire_in_s, setting defining the amount of seconds needed to expire a listed IP-address
            - settings.primary_idp_key, the key in redis that stored the name of the primary IDP (as configured in the IDP configurations).

        Optional settings:
            - settings.overflow_idp_key, enable an overflow IDP. If the primary idp is limited, attempt this configuration.
            the value stored in the redis store under this key, should be the name of one of the configured IDPs.
            - settings.ratelimit.user_limit_key, if defined, the ratelimiter is active on the primary IDP and allows the number of connections
            as defined in redis under this key.
            - settings.ratelimit.user_limit_overflow_idp, if defined, the ratelimiter is active for the overflow idp as well. Defines, in the redis store,
            the number of active connections allowed.

        :param user_limit_key: the key in the redis store that defines the number of allowed users per 10th of a second
        :raises: TooBusyError when the number of users exceeds the allowed number.
        """
        try:
            ip_cache_in_s: int  = int(self.settings.ratelimit.ip_expire_in_s)

            if hasattr(self.settings.ratelimit, "nof_attempts_s") and self.settings.ratelimit.nof_attempts_s != "":
                # Optional config setting
                nof_attempts_s: int = int(self.settings.ratelimit.nof_attempts_s)
                self.ip_limit_test(ip_address=ip_address, ip_expire_s=ip_cache_in_s, nof_attempts_s=nof_attempts_s)
            else:
                self.ip_limit_test(ip_address=ip_address, ip_expire_s=ip_cache_in_s)
        except TypeError as int_cast_err:
            raise ValueError(
                "Please check the ratelimit.ip_expire_in_s setting, can it be parsed as integer?"
            ) from int_cast_err

        primary_idp = self.redis_client.get(self.settings.primary_idp_key)
        if primary_idp is not None:
            primary_idp = primary_idp.decode()
        else:
            raise ExpectedRedisValue(f"Expected {self.settings.primary_idp_key} key to be set in redis. Please check the primary_idp_key setting")

        overflow_idp = self.redis_client.get(self.settings.overflow_idp_key)

        if overflow_idp and overflow_idp.decode().lower() != 'false':
            overflow_idp = overflow_idp.decode()
            try:
                self.user_limit_test(idp_prefix=primary_idp, user_limit_key=self.settings.ratelimit.user_limit_key)
                return primary_idp
            except TooBusyError:
                self.user_limit_test(idp_prefix=overflow_idp, user_limit_key=self.settings.ratelimit.user_limit_key_overflow_idp)
                return overflow_idp
        else:
            self.user_limit_test(idp_prefix=primary_idp, user_limit_key=self.settings.ratelimit.user_limit_key)
            return primary_idp
