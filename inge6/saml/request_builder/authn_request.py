from lxml import etree
import secrets

from ...config import settings
from .saml_request import SamlRequest

class AuthNRequest(SamlRequest):
    TEMPLATE_PATH = settings.saml.authn_request_template

    def __init__(self) -> None:
        super().__init__()
        self.root = etree.parse(self.TEMPLATE_PATH).getroot()

        self._add_root_id(self.root)
        self._add_root_issue_instant(self.root)
        self._add_reference()
        self._add_certs()
        self._sign(self.root)

if __name__ == "__main__":
    test = AuthNRequest()
    print(test.get_xml().decode())
    print(test.get_base64_string().decode())