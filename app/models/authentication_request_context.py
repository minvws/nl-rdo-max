from typing import Any

from pydantic import BaseModel


class UserinfoContext(BaseModel):
    client_id: str
    authentication_method: str
    access_token: str
    # sub: str
    userinfo: Any
