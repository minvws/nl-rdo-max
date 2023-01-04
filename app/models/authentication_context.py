from typing import Any, Dict

from pydantic import BaseModel
from pyop.message import AuthorizationRequest


class AuthenticationContext(BaseModel):
    authorization_request: AuthorizationRequest
    authorization_by_proxy: bool
    authentication_method: str
    authentication_state: Dict[str, Any]

    class Config:
        arbitrary_types_allowed = True
