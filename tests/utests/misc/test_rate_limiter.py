import pytest

from unittest.mock import MagicMock, patch, call

from app.exceptions.max_exceptions import TooBusyError, TooManyRequestsFromOrigin, DependentServiceOutage
from app.misc.rate_limiter import RateLimiter
from app.storage.cache import Cache
from freezegun import freeze_time

ipok: str = "identity_provider_outage_key"
pipk: str = "primary_identity_provider_key"
oipk: str = "overflow_identity_provider_key"
pipulk: str = "primary_identity_provider_user_limit_key"
oipulk: str = "overflow_identity_provider_user_limit_key"
iamc = 2245
iamces = 245


def create_rate_limiter(
    cache: Cache = MagicMock(),
    identity_provider_outage_key: str = ipok,
    primary_identity_provider_key: str = pipk,
    overflow_identity_provider_key: str = oipk,
    primary_identity_provider_user_limit_key: str = pipulk,
    overflow_identity_provider_user_limit_key: str = oipulk,
    ip_address_max_count: int = iamc,
    ip_address_max_count_expire_seconds: int = iamces
) -> RateLimiter:
    return RateLimiter(
        cache,
        identity_provider_outage_key,
        primary_identity_provider_key,
        overflow_identity_provider_key,
        primary_identity_provider_user_limit_key,
        overflow_identity_provider_user_limit_key,
        ip_address_max_count,
        ip_address_max_count_expire_seconds
    )


def test_get_identity_provider_name_and_validate_request_happy_path():
    with patch.object(RateLimiter, '_get_primary_identity_provider_name', return_value="pipn") \
            as get_primary_idp_method, \
            patch.object(RateLimiter, '_ip_limit_test') \
            as ip_limit_test_method, \
            patch.object(RateLimiter, '_user_limit_test') \
            as user_limit_test_method, \
            patch.object(RateLimiter, '_get_overflow_identity_provider_name') \
            as get_overflow_idp_method:
        rl = create_rate_limiter(
            primary_identity_provider_user_limit_key="pipulk",
            overflow_identity_provider_user_limit_key="oipulk"
        )
        actual = rl.get_identity_provider_name_and_validate_request("ipaddress")
        assert actual == "pipn"
        ip_limit_test_method.assert_called_with(ipaddress='ipaddress')
        get_primary_idp_method.assert_called()
        user_limit_test_method.assert_called_with(user_limit_key="pipulk", identity_provider_name="pipn")
        get_overflow_idp_method.assert_not_called()


def test_get_identity_provider_name_and_validate_request_with_too_many_users_for_oidp():
    with patch.object(RateLimiter, '_get_primary_identity_provider_name', return_value="pipn") \
            as get_primary_idp_method, \
            patch.object(RateLimiter, '_ip_limit_test') \
            as ip_limit_test_method, \
            patch.object(RateLimiter, '_user_limit_test', side_effect=TooBusyError()) \
            as user_limit_test_method, \
            patch.object(RateLimiter, '_get_overflow_identity_provider_name', return_value="oipn") \
            as get_overflow_idp_method:
        rl = create_rate_limiter(
            primary_identity_provider_user_limit_key="pipulk",
            overflow_identity_provider_user_limit_key="oipulk"
        )
        with pytest.raises(TooBusyError):
            rl.get_identity_provider_name_and_validate_request("ipaddress")
        ip_limit_test_method.assert_called_with(ipaddress='ipaddress')
        get_primary_idp_method.assert_called()
        user_limit_test_method.assert_has_calls([
            call(user_limit_key="pipulk", identity_provider_name="pipn"),
            call(user_limit_key="oipulk", identity_provider_name="oipn")])
        get_overflow_idp_method.assert_called()


def test_get_identity_provider_name_and_validate_request_with_too_many_users_for_pidp():
    with patch.object(RateLimiter, '_get_primary_identity_provider_name', return_value="pipn") \
            as get_primary_idp_method, \
            patch.object(RateLimiter, '_ip_limit_test') \
            as ip_limit_test_method, \
            patch.object(RateLimiter, '_user_limit_test', side_effect=[TooBusyError(), None]) \
            as user_limit_test_method, \
            patch.object(RateLimiter, '_get_overflow_identity_provider_name', return_value="oipn") \
            as get_overflow_idp_method:
        rl = create_rate_limiter(
            primary_identity_provider_user_limit_key="pipulk",
            overflow_identity_provider_user_limit_key="oipulk"
        )
        actual = rl.get_identity_provider_name_and_validate_request("ipaddress")
        assert actual == "oipn"
        ip_limit_test_method.assert_called_with(ipaddress='ipaddress')
        get_primary_idp_method.assert_called()
        user_limit_test_method.assert_has_calls([
            call(user_limit_key="pipulk", identity_provider_name="pipn"),
            call(user_limit_key="oipulk", identity_provider_name="oipn")])
        get_overflow_idp_method.assert_called()


def test_get_identity_provider_name_and_validate_request_when_too_many_requests_from_origin():
    with patch.object(RateLimiter, '_ip_limit_test', side_effect=TooManyRequestsFromOrigin("")) \
            as ip_limit_test_method, \
            patch.object(RateLimiter, '_get_primary_identity_provider_name') \
            as get_primary_idp_method, \
            patch.object(RateLimiter, '_user_limit_test') \
            as user_limit_test_method, \
            patch.object(RateLimiter, '_get_overflow_identity_provider_name') \
            as get_overflow_idp_method:
        rl = create_rate_limiter()
        with pytest.raises(TooManyRequestsFromOrigin):
            rl.get_identity_provider_name_and_validate_request("ipaddress")
        ip_limit_test_method.assert_called_with(ipaddress='ipaddress')
        get_primary_idp_method.assert_not_called()
        user_limit_test_method.assert_not_called()
        get_overflow_idp_method.assert_not_called()


def test_validate_outage():
    cache = MagicMock()
    cache.get_bool.return_value = False
    rl = create_rate_limiter(cache, identity_provider_outage_key="ipok")
    rl.validate_outage()
    cache.get_bool.assert_called_with("ipok")


def test_validate_outage_when_cache_returns_true():
    cache = MagicMock()
    cache.get_bool.return_value = True
    rl = create_rate_limiter(cache, identity_provider_outage_key="ipok")
    with pytest.raises(DependentServiceOutage):
        rl.validate_outage()
    cache.get_bool.assert_called_with("ipok")


def test_validate_outage_without_provider_outage_key():
    assert None is create_rate_limiter(identity_provider_outage_key=None).validate_outage()


def test_ip_limit_test():
    with patch.object(RateLimiter, '_increase_ip_count', return_value=6) as mock_method:
        rl = create_rate_limiter(ip_address_max_count=6)
        rl._ip_limit_test("ipaddress")

        mock_method.assert_called_with("ipaddress")


def test_ip_limit_test_raises_too_many_requests():
    with patch.object(RateLimiter, '_increase_ip_count', return_value=7) as mock_method:
        rl = create_rate_limiter(ip_address_max_count=6)

        with pytest.raises(TooManyRequestsFromOrigin):
            rl._ip_limit_test("ipaddress")

        mock_method.assert_called_with("ipaddress")


@freeze_time("2022-05-12 12:11:10")
def test_user_limit_test_over_limit():
    with patch.object(RateLimiter, '_increase_user_count', return_value=3) as mock_method:
        user_limit_key = "ulk"
        identity_provider_name = "idp"
        user_limit = 2
        cache = MagicMock()
        cache.get_int.return_value = user_limit
        rl = create_rate_limiter(cache)

        with pytest.raises(TooBusyError):
            rl._user_limit_test(user_limit_key, identity_provider_name)

        cache.get_int.assert_called_with(user_limit_key)
        mock_method.assert_called_with(identity_provider_name, '1652357470')


@freeze_time("2022-05-12 12:11:10")
def test_user_limit_test_within_limit():
    with patch.object(RateLimiter, '_increase_user_count', return_value=3) as mock_method:
        user_limit_key = "ulk"
        identity_provider_name = "idp"
        user_limit = 4
        cache = MagicMock()
        cache.get_int.return_value = user_limit
        rl = create_rate_limiter(cache)

        rl._user_limit_test(user_limit_key, identity_provider_name)

        cache.get_int.assert_called_with(user_limit_key)
        mock_method.assert_called_with(identity_provider_name, '1652357470')


def test_user_limit_test_without_limit_in_cache():
    user_limit_key = "ulk"
    identity_provider_name = "idp"
    cache = MagicMock()
    cache.get_int.return_value = None
    rl = create_rate_limiter(cache)
    assert rl._user_limit_test(user_limit_key, identity_provider_name) is None


def test_increase_ip_count():
    cache = MagicMock()
    expected = 4
    cache.incr.return_value = expected
    rl = create_rate_limiter(cache)
    actual = rl._increase_ip_count("ipaddress")
    cache.incr.assert_called_with("ipv4:ipaddress")
    cache.expire.assert_called_with("ipv4:ipaddress", iamces)
    assert actual == expected


def test_increase_user_count():
    cache = MagicMock()
    expected = 2
    cache.incr.return_value = expected
    rl = create_rate_limiter(cache)
    actual = rl._increase_user_count("idp", "timeslot")
    cache.incr.assert_called_with("timeslot")
    cache.expire.assert_called_with("max:limiter:idp:timeslot", 2)
    assert actual == expected


def test_get_primary_identity_provider_name():
    cache = MagicMock()
    expected = "mock_return_value"
    cache.get_string.return_value = expected
    rate_limiter = create_rate_limiter(cache)
    get_primary_identity_provider_name = rate_limiter._get_primary_identity_provider_name()
    assert get_primary_identity_provider_name == expected
    cache.get_string.assert_called_with(pipk)


def test_get_overflow_identity_provider_name():
    cache = MagicMock()
    expected = "mock_return_value"
    cache.get_string.return_value = expected
    rate_limiter = create_rate_limiter(cache)
    get_overflow_identity_provider_name = rate_limiter._get_overflow_identity_provider_name()
    assert get_overflow_identity_provider_name == expected
    cache.get_string.assert_called_with(oipk)


