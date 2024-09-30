from typing import Dict

from pydantic import BaseModel
from starlette.requests import Request

from app.exceptions.max_exceptions import ServerErrorException
from app.models.login_method import LoginMethod


class AuthenticationMeta(BaseModel):
    ip: str
    headers: Dict[str, str]
    authentication_method_name: str

    @classmethod
    def create_authentication_meta(
        cls, request: Request, authentication_method: LoginMethod
    ) -> "AuthenticationMeta":
        if request.client is None or request.client.host is None:
            raise ServerErrorException(
                error_description="No Client info available in the request content"
            )
        ip_address = request.client.host

        headers = {}
        for key, value in request.headers.items():
            headers.update({key: value})

        return cls(
            ip=ip_address,
            headers=headers,
            authentication_method_name=authentication_method.name,
        )
