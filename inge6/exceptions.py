
from oic.oic.message import TokenErrorResponse

class TooBusyError(RuntimeError):
    pass

class TooManyRequestsFromOrigin(RuntimeError):
    pass

class DependentServiceOutage(RuntimeError):
    pass

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
