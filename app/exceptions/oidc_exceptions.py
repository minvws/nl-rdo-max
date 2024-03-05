from dataclasses import dataclass
from typing import Protocol, Optional, Dict, Any
from configparser import ConfigParser

from app.misc.utils import json_from_file

config = ConfigParser()
config.read("max.conf")

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


lang_map = json_from_file(config.get("app", "oidc_error_map"))
language = config.get("app", "language")

_error_map: Dict[str, Any] = {
    "invalid_request": {"code": 400, "error_description": "Invalid request"},
    "unauthorized_client": {
        "code": 403,
        "error_description": "You are not authorized for this request",
    },
    "access_denied": {
        "code": 403,
        "error_description": "You need to be logged in for this request",
    },
    "unsupported_response_type": {
        "code": 400,
        "error_description": "The response type is not supported",
    },
    "invalid_scope": {
        "code": 400,
        "error_description": "The scope is not supported",
    },
    "server_error": {
        "code": 500,
        "error_description": "Something went wrong, try again later",
    },
    "temporarily_unavailable": {
        "code": 503,
        "error_description": "The services are temporarily unavailable, try again later",
    },
}


class OIDCErrorDetails(Protocol):
    code: int
    error_description: str


@dataclass
class OIDCErrorMapper:
    """
    Mapper class for OIDC errors

    Note: Make sure you check the language map in resources/lang/nl.oidc_error_map.json and
    _error_map dict before you make changes
    """
    invalid_request: OIDCErrorDetails
    unauthorized_client: OIDCErrorDetails
    access_denied: OIDCErrorDetails
    unsupported_response_type: OIDCErrorDetails
    invalid_scope: OIDCErrorDetails
    server_error: OIDCErrorDetails
    temporarily_unavailable: OIDCErrorDetails

    def __getitem__(self, key: str):
        if hasattr(self, key):
            return getattr(self, key)

        raise AttributeError(key)

    def get_error_code(self, error_type: Optional[str]) -> int:
        if error_type is not None:
            return self[error_type]["code"]

        return self.server_error.code

    def get_error_description(self, error_type: Optional[str]) -> str:
        if error_type is not None:
            return (
                self[error_type]["error_description"]
                if language == "en"
                else lang_map[self[error_type]["error_description"]]
            )

        return self.server_error.error_description


OICD_ERROR_MAPPER = OIDCErrorMapper(**_error_map)
