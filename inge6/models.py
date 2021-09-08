# pylint: disable=too-few-public-methods
import html
import json
import base64

from enum import Enum
from typing import Optional

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

class LoginDigiDRequest(BaseModel):
    state: str
    authorize_request: AuthorizeRequest
    force_digid: Optional[bool] = None
    idp_name: Optional[str] = None

    @validator('state')
    def convert_to_escaped_html(cls, text): # pylint: disable=no-self-argument, no-self-use
        return html.escape(text)

    @classmethod
    def from_request(
        cls,
        state: str,
        authorize_request: str,
        force_digid: Optional[bool] = None,
        idp_name: Optional[str] = None
    ) -> 'LoginDigiDRequest':
        return LoginDigiDRequest.parse_obj({
            'state': state,
            'authorize_request': AuthorizeRequest(
                **json.loads(
                    base64.urlsafe_b64decode(
                        authorize_request
                    )
                )
            ),
            'force_digid': force_digid,
            'idp_name': idp_name
        })

class DigiDMockRequest(BaseModel):
    state: str
    SAMLRequest: str
    RelayState: str
    idp_name: str
    authorize_request: str

    # pylint: disable=invalid-name
    @classmethod
    def from_request(
        cls,
        state: str,
        idp_name: str,
        authorize_request: str, # base64 encoded
        SAMLRequest: str = Form(...),
        RelayState: str = Form(...),
    ) -> 'DigiDMockRequest':
        return DigiDMockRequest.parse_obj({
            'SAMLRequest': SAMLRequest,
            'RelayState': RelayState,
            'idp_name': idp_name,
            'state': state,
            'authorize_request': authorize_request,
        })

    @validator('state', 'RelayState', 'SAMLRequest')
    def convert_to_escaped_html(cls, text): # pylint: disable=no-self-argument, no-self-use
        return html.escape(text)

class DigiDMockCatchRequest(BaseModel):
    bsn: str
    SAMLart: str
    RelayState: str

    @validator('bsn', 'SAMLart', 'RelayState')
    def convert_to_escaped_html(cls, text): # pylint: disable=no-self-argument, no-self-use
        return html.escape(text)

class SorryPageRequest(BaseModel):
    state: str
    redirect_uri: str
    client_id: str

    @validator('state', 'redirect_uri', 'client_id')
    def convert_to_escaped_html(cls, text): # pylint: disable=no-self-argument, no-self-use
        return html.escape(text)

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
