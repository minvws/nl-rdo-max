import abc
from typing import Union, Optional

from app.exceptions.oidc_exceptions import (
    UNAUTHORIZED_CLIENT,
    SERVER_ERROR,
    ACCESS_DENIED,
    TEMPORARILY_UNAVAILABLE,
    INVALID_REQUEST,
    INVALID_CLIENT,
)


class OIDCBaseException(Exception, abc.ABC):
    def __init__(
        self,
        *,
        error: str,
        error_description: str,
        log_message: Union[str, None] = None,
        status_code: int = 500,
    ):
        super().__init__(error_description if log_message is None else log_message)
        self.error = error
        self.error_description = error_description
        self.log_message = log_message
        self.status_code = status_code


class InvalidClientException(OIDCBaseException):
    """
    https://openid.net/specs/openid-connect-core-1_0.html#AuthError
    """

    def __init__(self, *, error_description):
        super().__init__(
            error=UNAUTHORIZED_CLIENT,
            error_description=error_description,
            status_code=400,
        )


class InvalidRedirectUriException(OIDCBaseException):
    def __init__(self):
        super().__init__(
            error=UNAUTHORIZED_CLIENT,
            error_description="Invalid redirect uri",
            status_code=400,
        )


class ServerErrorException(OIDCBaseException):
    def __init__(self, *, error_description: str, log_message: Union[str, None] = None):
        super().__init__(
            error=SERVER_ERROR,
            error_description=error_description,
            log_message=log_message,
            status_code=500,
        )


class UnauthorizedError(OIDCBaseException):
    def __init__(
        self,
        *,
        error=ACCESS_DENIED,
        error_description: str,
        status_code: int = 401,
        log_message: Union[str, None] = None,
    ):
        super().__init__(
            error=error,
            error_description=error_description,
            log_message=log_message,
            status_code=status_code,
        )


class DependentServiceOutage(OIDCBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description="Some service we depend on is down.",
            status_code=503,
        )


class TooManyRequestsFromOrigin(OIDCBaseException):
    def __init__(self, *, ip_expire_s: str) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description="Too many requests from the same ip_address during the last"
            f" {ip_expire_s} seconds.",
            status_code=429,
        )


class TooBusyError(OIDCBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description="Servers are too busy at this point, please try again later",
            status_code=503,
        )


class AuthorizationByProxyDisabled(OIDCBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=INVALID_REQUEST,
            error_description="Authorization by proxy is disabled for this provider",
            status_code=400,
        )


class UnexpectedAuthnBinding(OIDCBaseException):
    def __init__(self, *, error_description: str) -> None:
        super().__init__(
            error=SERVER_ERROR,
            error_description=error_description,
            status_code=503,
        )


class InvalidRequestException(OIDCBaseException):
    def __init__(
        self,
        *,
        error_description: str,
        log_message: Optional[str] = None,
        error: str = INVALID_REQUEST,
    ) -> None:
        super().__init__(
            error=error,
            error_description=error_description,
            log_message=log_message,
            status_code=400,
        )


class InvalidResponseType(OIDCBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=INVALID_REQUEST,
            error_description="Invalid response type",
            status_code=400,
        )


class InvalidCodeChallengeMethodException(OIDCBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=INVALID_REQUEST,
            error_description="Invalid code challenge method, code challenge method supported: S256",
            status_code=406,
        )


class InvalidClientAssertionException(OIDCBaseException):
    def __init__(self) -> None:
        super().__init__(
            error=INVALID_CLIENT,
            error_description="Client assertion failed, invalid JWT",
            status_code=401,
        )
