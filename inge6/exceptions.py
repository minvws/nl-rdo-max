
from oic.oic.message import TokenErrorResponse

class TooBusyError(RuntimeError):
    pass

class TooManyRequestsFromOrigin(RuntimeError):
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
