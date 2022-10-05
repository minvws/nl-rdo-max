import typing
import html
import json
import base64
from pydantic import BaseModel, validator
from app.models.authorize_request import AuthorizeRequest


class LoginDigiDRequest(BaseModel):
    state: str
    authorize_request: AuthorizeRequest
    force_digid: typing.Optional[bool] = None
    idp_name: typing.Optional[str] = None

    @validator("state")
    def convert_to_escaped_html(cls, text):  # pylint: disable=no-self-argument
        return html.escape(text)

    @classmethod
    def from_request(
        cls,
        state: str,
        authorize_request: str,
        force_digid: typing.Optional[bool] = None,
        idp_name: typing.Optional[str] = None,
    ) -> "LoginDigiDRequest":
        return LoginDigiDRequest.parse_obj(
            {
                "state": state,
                "authorize_request": AuthorizeRequest(
                    **json.loads(base64.urlsafe_b64decode(authorize_request))
                ),
                "force_digid": force_digid,
                "idp_name": idp_name,
            }
        )
