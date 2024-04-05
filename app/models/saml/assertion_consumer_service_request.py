import base64
import html
import json
import logging

import nacl.hash
from pydantic import BaseModel, field_validator

log = logging.getLogger(__name__)


class AssertionConsumerServiceRequest(BaseModel):
    SAMLart: str
    RelayState: str
    mocking: bool

    # pylint: disable=invalid-name
    # noinspection PyPep8Naming
    @staticmethod
    def from_request(
        SAMLart: str, RelayState: str, mocking: int = 0
    ) -> "AssertionConsumerServiceRequest":
        return AssertionConsumerServiceRequest.parse_obj(
            {"SAMLart": SAMLart, "RelayState": RelayState, "mocking": mocking == 1}
        )

    def hashed_saml_art(self):
        return nacl.hash.sha256(self.SAMLart.encode()).decode()

    @staticmethod
    @field_validator("SAMLart", "RelayState")
    def convert_to_escaped_html(text):  # pylint: disable=no-self-argument
        return html.escape(text)

    @property
    def state(self) -> dict:
        try:
            return json.loads(base64.urlsafe_b64decode(self.RelayState))
        except Exception:  # pylint:disable=broad-except
            log.debug("unable to decode state param")
            return {}

    @property
    def client_id(self):
        return self.state["client_id"]
