# pylint:disable=protected-access
from unittest.mock import MagicMock, patch, call

import pytest
from freezegun import freeze_time

from app.exceptions.max_exceptions import (
    TooBusyError,
    TooManyRequestsFromOrigin,
    DependentServiceOutage,
)
from app.misc.rate_limiter import RateLimiter
from app.storage.cache import Cache

ipok: str = "identity_provider_outage_key"
pipk: str = "primary_identity_provider_key"
oipk: str = "overflow_identity_provider_key"
pipulk: str = "primary_identity_provider_user_limit_key"
oipulk: str = "overflow_identity_provider_user_limit_key"
IAMC = 2245
IAMCES = 245


def create_rate_limiter(
    cache: Cache = MagicMock(),
    identity_provider_outage_key: str = ipok,
    primary_identity_provider_key: str = pipk,
    overflow_identity_provider_key: str = oipk,
    primary_identity_provider_user_limit_key: str = pipulk,
    overflow_identity_provider_user_limit_key: str = oipulk,
    ip_address_max_count: int = IAMC,
    ip_address_max_count_expire_seconds: int = IAMCES,
) -> RateLimiter:
    return RateLimiter(
        cache,
        identity_provider_outage_key,
        primary_identity_provider_key,
        overflow_identity_provider_key,
        primary_identity_provider_user_limit_key,
        overflow_identity_provider_user_limit_key,
        ip_address_max_count,
        ip_address_max_count_expire_seconds,
    )


def test_get_identity_provider_name_based_on_request_limits_happy_path():
    with patch.object(
        RateLimiter, "_get_primary_identity_provider_name", return_value="pipn"
    ) as get_primary_idp_method, patch.object(
        RateLimiter, "_user_limit_test"
    ) as user_limit_test_method, patch.object(
        RateLimiter, "_get_overflow_identity_provider_name"
    ) as get_overflow_idp_method:
        rate_limiter = create_rate_limiter(
            primary_identity_provider_user_limit_key="pipulk",
            overflow_identity_provider_user_limit_key="oipulk",
        )
        actual = rate_limiter.get_identity_provider_name_based_on_request_limits()
        assert actual == "pipn"
        get_primary_idp_method.assert_called()
        user_limit_test_method.assert_called_with(
            user_limit_key="pipulk", identity_provider_name="pipn"
        )
        get_overflow_idp_method.assert_not_called()


def test_get_identity_provider_name_based_on_request_limits_with_too_many_users_for_oidp():
    with patch.object(
        RateLimiter, "_get_primary_identity_provider_name", return_value="pipn"
    ) as get_primary_idp_method, patch.object(
        RateLimiter, "_user_limit_test", side_effect=TooBusyError()
    ) as user_limit_test_method, patch.object(
        RateLimiter, "_get_overflow_identity_provider_name", return_value="oipn"
    ) as get_overflow_idp_method:
        rate_limiter = create_rate_limiter(
            primary_identity_provider_user_limit_key="pipulk",
            overflow_identity_provider_user_limit_key="oipulk",
        )
        with pytest.raises(TooBusyError):
            rate_limiter.get_identity_provider_name_based_on_request_limits()
        get_primary_idp_method.assert_called()
        user_limit_test_method.assert_has_calls(
            [
                call(user_limit_key="pipulk", identity_provider_name="pipn"),
                call(user_limit_key="oipulk", identity_provider_name="oipn"),
            ]
        )
        get_overflow_idp_method.assert_called()


def test_get_identity_provider_name_based_on_request_limits_with_too_many_users_for_pidp():
    with patch.object(
        RateLimiter, "_get_primary_identity_provider_name", return_value="pipn"
    ) as get_primary_idp_method, patch.object(
        RateLimiter,
        "_user_limit_test",
        side_effect=[TooBusyError(), None],
    ) as user_limit_test_method, patch.object(
        RateLimiter, "_get_overflow_identity_provider_name", return_value="oipn"
    ) as get_overflow_idp_method:
        rate_limiter = create_rate_limiter(
            primary_identity_provider_user_limit_key="pipulk",
            overflow_identity_provider_user_limit_key="oipulk",
        )
        actual = rate_limiter.get_identity_provider_name_based_on_request_limits()
        assert actual == "oipn"
        get_primary_idp_method.assert_called()
        user_limit_test_method.assert_has_calls(
            [
                call(user_limit_key="pipulk", identity_provider_name="pipn"),
                call(user_limit_key="oipulk", identity_provider_name="oipn"),
            ]
        )
        get_overflow_idp_method.assert_called()


def test_validate_outage():
    cache = MagicMock()
    cache.get_bool.return_value = False
    rate_limiter = create_rate_limiter(cache, identity_provider_outage_key="ipok")
    rate_limiter.validate_outage()
    cache.get_bool.assert_called_with("ipok")


def test_validate_outage_when_cache_returns_true():
    cache = MagicMock()
    cache.get_bool.return_value = True
    rate_limiter = create_rate_limiter(cache, identity_provider_outage_key="ipok")
    with pytest.raises(DependentServiceOutage):
        rate_limiter.validate_outage()
    cache.get_bool.assert_called_with("ipok")


def test_validate_outage_without_provider_outage_key():
    assert (
        None is create_rate_limiter(identity_provider_outage_key=None).validate_outage()
    )


def test_ip_limit_test():
    with patch.object(RateLimiter, "_increase_ip_count", return_value=6) as mock_method:
        rate_limiter = create_rate_limiter(ip_address_max_count=6)
        rate_limiter.ip_limit_test("ipaddress")

        mock_method.assert_called_with("ipaddress")


def test_ip_limit_test_raises_too_many_requests():
    with patch.object(RateLimiter, "_increase_ip_count", return_value=7) as mock_method:
        rate_limiter = create_rate_limiter(ip_address_max_count=6)

        with pytest.raises(TooManyRequestsFromOrigin):
            rate_limiter.ip_limit_test("ipaddress")

        mock_method.assert_called_with("ipaddress")


@freeze_time("2022-05-12 12:11:10")
def test_user_limit_test_over_limit():
    with patch.object(
        RateLimiter, "_increase_user_count", return_value=3
    ) as mock_method:
        user_limit_key = "ulk"
        identity_provider_name = "idp"
        user_limit = 2
        cache = MagicMock()
        cache.get_int.return_value = user_limit
        rate_limiter = create_rate_limiter(cache)

        with pytest.raises(TooBusyError):
            rate_limiter._user_limit_test(user_limit_key, identity_provider_name)

        cache.get_int.assert_called_with(user_limit_key)
        mock_method.assert_called_with(identity_provider_name, "1652357470")


@freeze_time("2022-05-12 12:11:10")
def test_user_limit_test_within_limit():
    with patch.object(
        RateLimiter, "_increase_user_count", return_value=3
    ) as mock_method:
        user_limit_key = "ulk"
        identity_provider_name = "idp"
        user_limit = 4
        cache = MagicMock()
        cache.get_int.return_value = user_limit
        rate_limiter = create_rate_limiter(cache)

        rate_limiter._user_limit_test(user_limit_key, identity_provider_name)

        cache.get_int.assert_called_with(user_limit_key)
        mock_method.assert_called_with(identity_provider_name, "1652357470")


def test_user_limit_test_without_limit_in_cache():
    user_limit_key = "ulk"
    identity_provider_name = "idp"
    cache = MagicMock()
    cache.get_int.return_value = None
    rate_limiter = create_rate_limiter(cache)
    assert rate_limiter._user_limit_test(user_limit_key, identity_provider_name) is None


def test_increase_ip_count_without_expire():
    cache = MagicMock()
    expected = 4
    cache.incr.return_value = expected
    rate_limiter = create_rate_limiter(cache)
    actual = rate_limiter._increase_ip_count("ipaddress")
    cache.incr.assert_called_with("ip:ipaddress")
    assert actual == expected


def test_increase_ip_count():
    cache = MagicMock()
    expected = 2
    cache.incr.return_value = expected
    rate_limiter = create_rate_limiter(cache)
    actual = rate_limiter._increase_ip_count("ipaddress")
    cache.incr.assert_called_with("ip:ipaddress")
    cache.expire.assert_called_with("ip:ipaddress", IAMCES)
    assert actual == expected


def test_increase_user_count():
    cache = MagicMock()
    expected = 2
    cache.incr.return_value = expected
    rate_limiter = create_rate_limiter(cache)
    actual = rate_limiter._increase_user_count("idp", "timeslot")
    cache.incr.assert_called_with("max:limiter:idp:timeslot")
    cache.expire.assert_called_with("max:limiter:idp:timeslot", 2)
    assert actual == expected


def test_get_primary_identity_provider_name():
    cache = MagicMock()
    expected = "mock_return_value"
    cache.get_string.return_value = expected
    rate_limiter = create_rate_limiter(cache)
    get_primary_identity_provider_name = (
        rate_limiter._get_primary_identity_provider_name()
    )
    assert get_primary_identity_provider_name == expected
    cache.get_string.assert_called_with(pipk)


def test_get_overflow_identity_provider_name():
    cache = MagicMock()
    expected = "mock_return_value"
    cache.get_string.return_value = expected
    rate_limiter = create_rate_limiter(cache)
    get_overflow_identity_provider_name = (
        rate_limiter._get_overflow_identity_provider_name()
    )
    assert get_overflow_identity_provider_name == expected
    cache.get_string.assert_called_with(oipk)
