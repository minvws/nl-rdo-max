from typing import Any, Dict, Optional

from pydantic import BaseModel
from pyop.message import AuthorizationRequest


class AuthenticationContext(BaseModel):
    authorization_request: AuthorizationRequest
    authorization_by_proxy: bool
    authentication_method: str
    authentication_state: Dict[str, Any]
    session_id: str
    req_acme_token: Optional[str]

    class Config:
        arbitrary_types_allowed = True

    def to_dict(self):
        return {
            "authorization_request": self.authorization_request.to_dict(),
            "authorization_by_proxy": self.authorization_by_proxy,
            "authentication_method": self.authentication_method,
            "authentication_state": self.authentication_state,
            "session_id": self.session_id,
            "req_acme_token": self.req_acme_token,
        }

    @classmethod
    def from_dict(cls, dictionary: dict):
        authorization_request = AuthorizationRequest(
            **dictionary["authorization_request"]
        )
        return cls(
            authorization_request=authorization_request,
            authorization_by_proxy=dictionary["authorization_by_proxy"],
            authentication_method=dictionary["authentication_method"],
            authentication_state=dictionary["authentication_state"],
            session_id=dictionary["session_id"],
            req_acme_token=dictionary["req_acme_token"],
        )
