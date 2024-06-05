from typing import Dict

from pydantic import BaseModel
from starlette.requests import Request


class AuthenticationMeta(BaseModel):
    ip: str
    headers: Dict[str, str]

    @classmethod
    def create_authentication_meta(cls, request: Request) -> "AuthenticationMeta":
        ip_address = (
            request.client.host
            if request.client
            else "client host not found in request"
        )
        headers = {}
        for key, value in request.headers.items():
            headers.update({key: value})

        return cls(ip=ip_address, headers=headers)
