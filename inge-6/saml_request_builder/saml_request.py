import xmlsec
import base64
import secrets
from datetime import datetime
from lxml import etree

from ..config import settings

class SamlRequest:
    KEY_PATH = settings.saml.key_path
    CERT_PATH = settings.saml.cert_path

    def __init__(self):
        self.__id = "_" + secrets.token_hex(41) # total length 42.

    def _add_root_issue_instant(self, root):
        root.attrib['IssueInstant'] = datetime.utcnow().isoformat().split('.')[0] + 'Z'

    def _add_root_id(self, root):
        root.attrib['ID'] = self.__id

    def _add_reference(self):
        reference_node = xmlsec.tree.find_node(self.template, xmlsec.constants.NodeReference)
        reference_node.attrib['URI'] = f"#{self.__id}"

    def _add_certs(self):
        cert_node = self.template.find('.//ds:X509Certificate', {'ds': 'http://www.w3.org/2000/09/xmldsig#'})

        with open(self.CERT_PATH, 'r') as cert_file:
            cert_node.text = base64.b64encode(cert_file.read().encode())

    def _sign(self):
        signature_node = xmlsec.tree.find_node(self.template, xmlsec.constants.NodeSignature)
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_file(self.KEY_PATH, xmlsec.constants.KeyDataFormatPem)
        ctx.key = key
        ctx.register_id(self.template)
        ctx.sign(signature_node)

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)

    def get_base64_string(self) -> str:
        return base64.b64encode(self.get_xml())