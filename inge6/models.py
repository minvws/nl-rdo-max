# pylint: disable=too-few-public-methods
from enum import Enum

from fastapi import Form
from pydantic import BaseModel

class ResponseType(str, Enum):
    CODE: str = "code"

    def __str__(self) -> str: # pylint: disable=invalid-str-returned
        return self.CODE.value

class AuthorizeRequest(BaseModel):
    client_id: str
    redirect_uri: str
    response_type: ResponseType
    nonce: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str

class AccesstokenRequest(BaseModel):
    code: str
    code_verifier: str
    state: str
    grant_type: str
    redirect_uri: str

    @classmethod
    def as_form(
        cls,
        code: str = Form(...),
        code_verifier: str = Form(...),
        state: str = Form(...),
        grant_type: str = Form(...),
        redirect_uri: str = Form(...)
    ):
        return cls(
                code=code,
                code_verifier=code_verifier,
                state=state,
                grant_type=grant_type,
                redirect_uri=redirect_uri
        )
