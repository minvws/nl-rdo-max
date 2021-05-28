from lxml import etree
import secrets

from .saml_request import SamlRequest

# from ..config import settings

class AuthNRequest(SamlRequest):
    TEMPLATE_PATH = '../saml/templates/xml/authn_request.xml'

    def __init__(self) -> None:
        super().__init__()
        self.template = etree.parse(self.TEMPLATE_PATH).getroot()

        self._add_root_id(self.template)
        self._add_reference()
        self._add_certs()
        self._sign()

if __name__ == "__main__":
    test = AuthNRequest()
    print(test.get_xml().decode())
    print(test.get_base64_string().decode())