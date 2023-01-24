import html

from fastapi import Form
from pydantic import BaseModel, validator


class DigiDMockRequest(BaseModel):
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
    ) -> "DigiDMockRequest":
        return DigiDMockRequest.parse_obj(
            {
                "SAMLRequest": SAMLRequest,
                "RelayState": RelayState,
                "idp_name": idp_name,
                "state": state,
                "authorize_request": authorize_request,
            }
        )

    @staticmethod
    @validator("state", "RelayState", "SAMLRequest")
    def convert_to_escaped_html(text):  # pylint: disable=no-self-argument
        return html.escape(text)


class DigiDMockCatchRequest(BaseModel):
    bsn: str
    SAMLart: str
    RelayState: str

    @staticmethod
    @validator("bsn", "SAMLart", "RelayState")
    def convert_to_escaped_html(text):  # pylint: disable=no-self-argument
        return html.escape(text)
