from typing import Any, Dict

from pydantic import BaseModel


class AcsContext(BaseModel):
    client_id: str
    authentication_method: str
    authentication_state: Dict[str, Any]
    userinfo: str
    sub: str

    def to_dict(self):
        return {
            "client_id": self.client_id,
            "authentication_method": self.authentication_method,
            "authentication_state": self.authentication_state,
            "userinfo": self.userinfo,
            "sub": self.sub,
        }

    @classmethod
    def from_dict(cls, dictonary: dict):
        return cls(
            client_id=dictonary["client_id"],
            authentication_method=dictonary["authentication_method"],
            authentication_state=dictonary["authentication_state"],
            userinfo=dictonary["userinfo"],
            sub=dictonary["sub"],
        )
