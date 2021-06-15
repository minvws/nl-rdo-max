from typing import Optional
from oic.oic.message import AuthorizationRequest

class OAuthError(ValueError):
    oauth_error:  str

    def __init__(self, message: str, oauth_error: str) -> None: ...

class InvalidClientAuthentication(OAuthError):
    def __init__(self, message: str): ...

class InvalidRequestError(OAuthError):
    def __init__(self, message: str, parsed_request: AuthorizationRequest, oauth_error: str): ...

class InvalidAuthenticationRequest(InvalidRequestError):
    def __init__(self, message: str, parsed_request: AuthorizationRequest, oauth_error: str=...): ...
    def to_error_url(self) -> Optional[str]: ...

