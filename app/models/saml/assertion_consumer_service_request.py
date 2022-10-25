from pydantic import BaseModel, validator
import html
import nacl.hash


class AssertionConsumerServiceRequest(BaseModel):
    SAMLart: str
    RelayState: str
    mocking: bool

    # pylint: disable=invalid-name
    # noinspection PyPep8Naming
    @classmethod
    def from_request(
        cls, SAMLart: str, RelayState: str, mocking: int = 0
    ) -> "AssertionConsumerServiceRequest":
        return AssertionConsumerServiceRequest.parse_obj(
            {"SAMLart": SAMLart, "RelayState": RelayState, "mocking": mocking == 1}
        )

    def hashed_saml_art(self):
        return nacl.hash.sha256(self.SAMLart.encode()).decode()

    @staticmethod
    @validator("SAMLart", "RelayState")
    def convert_to_escaped_html(cls, text):  # pylint: disable=no-self-argument
        return html.escape(text)
