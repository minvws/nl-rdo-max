INVALID_REQUEST = "invalid_request"
UNAUTHORIZED_CLIENT = "unauthorized_client"
ACCESS_DENIED = "access_denied"
UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
INVALID_SCOPE = "invalid_scope"
SERVER_ERROR = "server_error"
TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"

INTERACTION_REQUIRED = "interaction_required"
LOGIN_REQUIRED = "login_required"
ACCOUNT_SELECTION_REQUIRED = "account_selection_required"
CONSENT_REQUIRED = "consent_required"
INVALID_REQUEST_URI = "invalid_request_uri"
INVALID_REQUEST_OBJECT = "invalid_request_object"
REQUEST_NOT_SUPPORTED = "request_not_supported"
REQUEST_URI_NOT_SUPPORTED = "request_uri_not_supported"
REGISTRATION_NOT_SUPPORTED = "registration_not_supported"


EXCEPTION_MAPPING = {
    "invalid_request": {
        "code": 400,
        "error_description": "Misvormd of slecht verzoek"
    },
    "unauthorized_client": {
        "code": 403,
        "error_description": "Klant is niet bevoegd een verzoek uit te voeren",
    },
    "access_denied": {
        "code": 403,
        "error_description": "Klant heeft geen toegang om bronnen aan te vragen",
    },
    "unsupported_response_type": {
        "code": 400,
        "error_description": "Response type wordt niet ondersteund",
    },
    "invalid_scope": {
        "code": 400,
        "error_description": "Client Scope wordt niet ondersteund",
    },
    "server_error": {
        "code": 500,
        "error_description": "Er is iets misgegaan. Probeer het later opnieuw",
    },
    "temporarily_unavailable": {
        "code": 503,
        "error_description": "De service is tijdelijk niet beschikbaar. Probeer het later opnieuw",
    },
}
