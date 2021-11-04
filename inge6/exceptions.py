from oic.oic.message import TokenErrorResponse


class InvalidClientError(RuntimeError):
    pass


class AuthorizeEndpointException(RuntimeError):
    def __init__(self, error: str, error_description: str, *args: object) -> None:
        super().__init__(*args)
        self.error = error
        self.error_description = error_description


class SomethingWrongError(RuntimeError):
    pass


class TooBusyError(SomethingWrongError):
    def __init__(self) -> None:
        super().__init__("Servers are too busy at this point, please try again later")


class TooManyRequestsFromOrigin(SomethingWrongError):
    def __init__(self, ip_expire_s: int) -> None:
        super().__init__(
            f"Too many requests from the same ip_address during the last {ip_expire_s} seconds."
        )


class DependentServiceOutage(SomethingWrongError):
    def __init__(self, outage_key: str) -> None:
        super().__init__(
            f"Some service we depend on is down according to the redis key: {outage_key}"
        )


class ExpiredResourceError(RuntimeError):
    pass


class ExpectedRedisValue(RuntimeError):
    pass


class UnexpectedAuthnBinding(RuntimeError):
    pass


# pylint: disable=too-many-ancestors
class TokenSAMLErrorResponse(TokenErrorResponse):
    c_allowed_values = TokenErrorResponse.c_allowed_values.copy()
    c_allowed_values.update(
        {
            "error": [
                "saml_authn_failed",
            ]
        }
    )
