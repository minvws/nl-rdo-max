from typing import Any, Union

from pydantic import BaseModel


class UserinfoContext(BaseModel):
    client_id: str
    authentication_method: str
    access_token: str
    userinfo: Any
    client_content_type: Union[str, None] = None
