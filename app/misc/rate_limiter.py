from datetime import datetime

from app.storage.cache import Cache
from app.exceptions.max_exceptions import (
    TooManyRequestsFromOrigin,
    TooBusyError,
    ExpectedCacheValue,
    DependentServiceOutage
)


class RateLimiter:
    def __init__(
        self,
        cache: Cache,
        identity_provider_outage_key: str,
        primary_identity_provider_key: str,
        overflow_identity_provider_key: str,
        primary_identity_provider_user_limit_key: str,
        overflow_identity_provider_user_limit_key: str,
        ipaddress_max_count: int,
        ipaddress_max_count_expire_seconds: int
    ):
        self._cache = cache
        self._identity_provider_outage_key = identity_provider_outage_key
        self._primary_identity_provider_key = primary_identity_provider_key
        self._overflow_identity_provider_key = overflow_identity_provider_key
        self._primary_identity_provider_user_limit_key = primary_identity_provider_user_limit_key
        self._overflow_identity_provider_user_limit_key = overflow_identity_provider_user_limit_key
        self._ipaddress_max_count = ipaddress_max_count
        self._ipaddress_max_count_expire_seconds = ipaddress_max_count_expire_seconds

    def get_identity_provider_name_and_validate_request(
        self,
        ipaddress: str
    ) -> str:
        primary_idp = self._get_primary_identity_provider_name()
        self._ip_limit_test(
            ipaddress=ipaddress,
            identity_provider_name=primary_idp
        )

        try:
            self._user_limit_test(
                user_limit_key=self._primary_identity_provider_user_limit_key,
                identity_provider_name=primary_idp
            )
            return primary_idp
        except TooBusyError as too_busy_error:
            overflow_idp = self._get_overflow_identity_provider_name()
            if overflow_idp is not None:
                self._user_limit_test(
                    user_limit_key=self._overflow_identity_provider_user_limit_key,
                    identity_provider_name=overflow_idp
                )
                return overflow_idp
            raise too_busy_error

    def validate_outage(self):
        if self._identity_provider_outage_key:
            if self._cache.get_bool(self._identity_provider_outage_key):
                raise DependentServiceOutage(
                    self._identity_provider_outage_key
                    if self._identity_provider_outage_key is not None
                    else ""
                )

    def _ip_limit_test(
        self,
        ipaddress: str,
        identity_provider_name: str
    ) -> None:
        current_count = self._increase_ip_count(identity_provider_name, ipaddress)
        if current_count > self._ipaddress_max_count:
            raise TooManyRequestsFromOrigin(self._ipaddress_max_count_expire_seconds)

    def _user_limit_test(
        self,
        user_limit_key: str,
        identity_provider_name: str
    ) -> None:
        user_limit = self._cache.get_int(user_limit_key)
        if user_limit is None:
            return

        timeslot = str(int(datetime.utcnow().timestamp()))

        num_users = self._increase_user_count(identity_provider_name, timeslot)
        if num_users > user_limit:
            raise TooBusyError()

    def _increase_ip_count(self, identity_provider_name, ipaddress):
        ip_key = f"{identity_provider_name}:ipv4:{ipaddress}"
        count = self._cache.incr(ip_key)
        self._cache.expire(ip_key, self._ipaddress_max_count_expire_seconds)
        return count

    def _increase_user_count(self, identity_provider_name, timeslot):
        idp = identity_provider_name.upper()
        timeslot_key = f"max:limiter:{idp}:{timeslot}"
        count = self._cache.incr(timeslot)
        self._cache.expire(timeslot_key, 2)
        return count

    def _get_primary_identity_provider_name(self):
        return self._cache.get_string(self._primary_identity_provider_key)

    def _get_overflow_identity_provider_name(self):
        return self._cache.get_string(self._overflow_identity_provider_key)
