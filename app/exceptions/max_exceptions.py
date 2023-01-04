import abc
from typing import Union

from app.exceptions.oidc_exceptions import (
    UNAUTHORIZED_CLIENT, SERVER_ERROR, ACCESS_DENIED, TEMPORARILY_UNAVAILABLE,
    INVALID_REQUEST,
)


class RedirectBaseException(Exception, abc.ABC):
    def __init__(
            self,
            *,
            error: str,
            error_description: str,
            redirect_uri: Union[str, None]
    ):
        super().__init__(error_description)
        self.error = error
        self.error_description = error_description
        self.redirect_uri = redirect_uri


class JsonBaseException(RedirectBaseException, abc.ABC):
    def __init__(
            self,
            *,
            error: str,
            error_description: str,
            redirect_uri: Union[str, None]
    ):
        super().__init__(error=error, error_description=error_description, redirect_uri=redirect_uri)


class TemplateBaseException(RedirectBaseException, abc.ABC):
    def __init__(
            self,
            *,
            error: str,
            error_description: str,
            redirect_uri: Union[str, None]
    ):
        super().__init__(error=error, error_description=error_description, redirect_uri=redirect_uri)


class InvalidClientException(TemplateBaseException):
    """
    https://openid.net/specs/openid-connect-core-1_0.html#AuthError
    """

    def __init__(
            self,
            *,
            error_description,
            redirect_uri: Union[str, None]
    ):
        super().__init__(
            error=UNAUTHORIZED_CLIENT,
            error_description=error_description,
            redirect_uri=redirect_uri
        )


class InvalidRedirectUriException(TemplateBaseException):
    def __init__(
            self,
            *,
            redirect_uri: Union[str, None]
    ):
        super().__init__(
            error=UNAUTHORIZED_CLIENT,
            error_description="Invalid redirect uri",
            redirect_uri=redirect_uri
        )


class ServerErrorException(JsonBaseException):
    def __init__(
            self,
            *,
            error_description: str,
            redirect_uri: Union[str, None]
    ):
        super().__init__(
            error=SERVER_ERROR,
            error_description=error_description,
            redirect_uri=redirect_uri
        )


class UnauthorizedError(JsonBaseException):
    def __init__(
            self,
            *,
            error_description: str,
            redirect_uri: Union[str, None]
    ):
        super().__init__(
            error=ACCESS_DENIED,
            error_description=error_description,
            redirect_uri=redirect_uri
        )


class DependentServiceOutage(JsonBaseException):
    def __init__(self, *, redirect_uri: Union[str, None]) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description="Some service we depend on is down.",
            redirect_uri=redirect_uri
        )


class TooManyRequestsFromOrigin(JsonBaseException):
    def __init__(
            self,
            *,
            ip_expire_s: str,
            redirect_uri: Union[str, None]
    ) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description=
            "Too many requests from the same ip_address during the last"
            f" {ip_expire_s} seconds.",
            redirect_uri=redirect_uri
        )


class TooBusyError(JsonBaseException):
    def __init__(self, *, redirect_uri: Union[str, None]) -> None:
        super().__init__(
            error=TEMPORARILY_UNAVAILABLE,
            error_description=
            "Servers are too busy at this point, please try again later",
            redirect_uri=redirect_uri
        )


class AuthorizationByProxyDisabled(JsonBaseException):
    def __init__(self, *, redirect_uri: Union[str, None]) -> None:
        super().__init__(
            error=INVALID_REQUEST,
            error_description=
            "Authorization by proxy is disabled for this provider",
            redirect_uri=redirect_uri
        )


class UnexpectedAuthnBinding(JsonBaseException):
    def __init__(self, *, redirect_uri: Union[str, None]) -> None:
        super().__init__(
            error=SERVER_ERROR,
            error_description="Unexpected Authn binding",
            redirect_uri=redirect_uri
        )
