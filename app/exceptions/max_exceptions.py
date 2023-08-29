import abc
from typing import Union

from app.exceptions.oidc_exceptions import (
    UNAUTHORIZED_CLIENT,
    SERVER_ERROR,
    ACCESS_DENIED,
    TEMPORARILY_UNAVAILABLE,
    INVALID_REQUEST,
    LOGIN_REQUIRED
)


class RedirectBaseException(Exception, abc.ABC):
    def __init__(
        self,
        *,
        error: str,
        error_description: str,
        log_message: Union[str, None] = None,
    ):
        super().__init__(error_description if log_message is None else log_message)
        self.error = error
        self.error_description = error_description


class JsonBaseException(RedirectBaseException, abc.ABC):
    pass


class TemplateBaseException(RedirectBaseException, abc.ABC):
    pass


class InvalidClientException(TemplateBaseException):
    """
    https://openid.net/specs/openid-connect-core-1_0.html#AuthError
    """

    def __init__(self, *, error_description):
        super().__init__(
            error=UNAUTHORIZED_CLIENT,
            error_description=error_description,
        )


class InvalidRedirectUriException(TemplateBaseException):
    def __init__(self):
        super().__init__(
            error=UNAUTHORIZED_CLIENT,
            error_description="Invalid redirect uri",
        )


class ServerErrorException(JsonBaseException):
    def __init__(self, *, error_description: str, log_message: Union[str, None] = None):
        super().__init__(
            error=SERVER_ERROR,
            error_description=error_description,
            log_message=log_message,
        )


class UnauthorizedError(JsonBaseException):
    def __init__(self, *, error_description: str, log_message: Union[str, None] = None):
        super().__init__(
            error=ACCESS_DENIED,
            error_description=error_description,
            log_message=log_message,
        )


class LoginCancelledError(JsonBaseException):
    def __init__(self, *, error_description: str, log_message: Union[str, None] = None):
        super().__init__(
            error=LOGIN_REQUIRED,
            error_description=error_description,
            log_message=log_message,
        )


class DependentServiceOutage(JsonBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description="Some service we depend on is down.",
        )


class TooManyRequestsFromOrigin(JsonBaseException):
    def __init__(self, *, ip_expire_s: str) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description="Too many requests from the same ip_address during the last"
            f" {ip_expire_s} seconds.",
        )


class TooBusyError(JsonBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description="Servers are too busy at this point, please try again later",
        )


class AuthorizationByProxyDisabled(JsonBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=INVALID_REQUEST,
            error_description="Authorization by proxy is disabled for this provider",
        )


class UnexpectedAuthnBinding(JsonBaseException):
    def __init__(self, *, error_description: str) -> None:
        super().__init__(
            error=SERVER_ERROR,
            error_description=error_description,
        )
