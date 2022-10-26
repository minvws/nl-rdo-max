import base64
import html
import json

from pydantic import BaseModel, validator

from app.models.authorize_request import AuthorizeRequest


class LoginDigiDMockRequest(BaseModel):
    state: str
    authorize_request: AuthorizeRequest
    idp_name: str
    force_digid: bool = False

    @validator("state")
    def convert_to_escaped_html(cls, text):  # pylint: disable=no-self-argument
        return html.escape(text)

    @classmethod
    def from_request(
        cls,
        state: str,
        authorize_request: str,
        idp_name: str,
        force_digid: bool = False,
    ) -> "LoginDigiDMockRequest":
        return LoginDigiDMockRequest.parse_obj(
            {
                "state": state,
                "authorize_request": AuthorizeRequest(
                    **json.loads(base64.urlsafe_b64decode(authorize_request))
                ),
                "force_digid": force_digid,
                "idp_name": idp_name,
            }
        )
