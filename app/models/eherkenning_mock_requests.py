import html

from fastapi import Form
from pydantic import BaseModel, field_validator


class EherkenningMockRequest(BaseModel):
    state: str
    SAMLRequest: str
    RelayState: str
    idp_name: str
    authorize_request: str

    # pylint: disable=invalid-name
    # noinspection PyPep8Naming
    @staticmethod
    def from_request(
        state: str,
        idp_name: str,
        authorize_request: str,  # base64 encoded
        SAMLRequest: str = Form(...),
        RelayState: str = Form(...),
    ) -> "EherkenningMockRequest":
        return EherkenningMockRequest.model_validate(
            {
                "SAMLRequest": SAMLRequest,
                "RelayState": RelayState,
                "idp_name": idp_name,
                "state": state,
                "authorize_request": authorize_request,
            }
        )

    @field_validator("state", "RelayState", "SAMLRequest")
    @classmethod
    def convert_to_escaped_html(cls, text):
        return html.escape(text)


class EherkenningMockCatchRequest(BaseModel):
    kvk: str
    SAMLart: str
    RelayState: str

    @field_validator("kvk", "SAMLart", "RelayState")
    @classmethod
    def convert_to_escaped_html(cls, text):
        return html.escape(text)
