# pylint: disable=too-few-public-methods
from enum import Enum

from .utils import escape_html

from fastapi import Form
from pydantic import BaseModel, validator

class ResponseType(str, Enum):
    CODE: str = "code"

    def __str__(self) -> str: # pylint: disable=invalid-str-returned
        return self.CODE

class AuthorizeRequest(BaseModel):
    client_id: str
    redirect_uri: str
    response_type: ResponseType
    nonce: str
    scope: str
    state: str
    code_challenge: str
    code_challenge_method: str

class DigiDMockRequest(BaseModel):
    state: str
    SAMLRequest: str
    RelayState: str

    @validator('state', 'SAMLRequest', 'RelayState')
    def convert_to_escaped_html(cls, text):
        return escape_html(text)

class DigiDMockCatchRequest(BaseModel):
    bsn: str
    SAMLart: str
    RelayState: str

    @validator('bsn', 'SAMLart', 'RelayState')
    def convert_to_escaped_html(cls, text):
        return escape_html(text)
      
class SorryPageRequest(BaseModel):
    state: str
    redirect_uri: str
    client_id: str

    @validator('state', 'redirect_uri', 'client_id')
    def convert_to_escaped_html(cls, text):
        return escape_html(text)

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
