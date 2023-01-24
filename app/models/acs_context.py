from typing import Any, Dict

from pydantic import BaseModel


class AcsContext(BaseModel):
    client_id: str
    authentication_method: str
    authentication_state: Dict[str, Any]
    userinfo: Any
