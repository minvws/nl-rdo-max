from app.models.enums import SomethingWrongReason


class ServerErrorException(Exception):
    def __init__(self) -> None:
        super().__init__()


class SomethingWrongError(RuntimeError):
    def __init__(self, reason: SomethingWrongReason, message: str):
        super().__init__(message)
        self.reason = reason


class DependentServiceOutage(SomethingWrongError):
    def __init__(self, outage_key: str) -> None:
        super().__init__(
            SomethingWrongReason.OUTAGE,
            "Some service we depend on is down.",
        )


class TooManyRequestsFromOrigin(SomethingWrongError):
    def __init__(self, ip_expire_s: str) -> None:
        super().__init__(
            SomethingWrongReason.TOO_MANY_REQUEST,
            f"Too many requests from the same ip_address during the last {ip_expire_s} seconds.",
        )


class TooBusyError(SomethingWrongError):
    def __init__(self) -> None:
        super().__init__(
            SomethingWrongReason.TOO_BUSY,
            "Servers are too busy at this point, please try again later",
        )


class ExpectedCacheValue(RuntimeError):
    pass


class AuthorizationByProxyDisabled(SomethingWrongError):
    def __init2__(self) -> None:
        super().__init__(
            SomethingWrongReason.AUTH_BY_PROXY_DISABLED,
            "Authorization by proxy is disabled for this provider",
        )


class UnexpectedAuthnBinding(RuntimeError):
    pass
