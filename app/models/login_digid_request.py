import base64
import html
import json

from pydantic import BaseModel, validator

from app.models.authorize_request import AuthorizeRequest


class LoginDigiDRequest(BaseModel):
    state: str
    authorize_request: AuthorizeRequest
    force_digid: bool = False

    @validator("state")
    def convert_to_escaped_html(cls, text):  # pylint: disable=no-self-argument
        return html.escape(text)

    @staticmethod
    def from_request(
        state: str,
        authorize_request: str,
        force_digid: bool = False,
    ) -> "LoginDigiDRequest":
        return LoginDigiDRequest.parse_obj(
            {
                "state": state,
                "authorize_request": AuthorizeRequest(
                    **json.loads(base64.urlsafe_b64decode(authorize_request))
                ),
                "force_digid": force_digid,
            }
        )
