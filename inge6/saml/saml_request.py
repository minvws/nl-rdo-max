import xmlsec
import base64
import secrets
from datetime import datetime
from lxml import etree

from ..config import settings

class SAMLRequest:
    KEY_PATH = settings.saml.key_path
    CERT_PATH = settings.saml.cert_path

    def __init__(self):
        self.__id = "_" + secrets.token_hex(41) # total length 42.

    def _add_root_issue_instant(self, root):
        root.attrib['IssueInstant'] = datetime.utcnow().isoformat().split('.')[0] + 'Z'

    def _add_root_id(self, root):
        root.attrib['ID'] = self.__id

    def _add_reference(self):
        reference_node = xmlsec.tree.find_node(self.root, xmlsec.constants.NodeReference)
        reference_node.attrib['URI'] = f"#{self.__id}"

    def _add_certs(self):
        cert_node = self.root.find('.//ds:X509Certificate', {'ds': 'http://www.w3.org/2000/09/xmldsig#'})

        with open(self.CERT_PATH, 'r') as cert_file:
            cert_node.text = base64.b64encode(cert_file.read().encode())

    def _sign(self, root):
        signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_file(self.KEY_PATH, xmlsec.constants.KeyDataFormatPem)
        ctx.key = key
        ctx.register_id(root)
        ctx.sign(signature_node)

    def get_xml(self) -> bytes:
        return etree.tostring(self.root)

    def get_base64_string(self) -> str:
        return base64.b64encode(self.get_xml())

class AuthNRequest(SAMLRequest):
    TEMPLATE_PATH = settings.saml.authn_request_template

    def __init__(self) -> None:
        super().__init__()
        self.root = etree.parse(self.TEMPLATE_PATH).getroot()

        self._add_root_id(self.root)
        self._add_root_issue_instant(self.root)
        self._add_reference()
        self._add_certs()
        self._sign(self.root)

class ArtifactResolveRequest(SAMLRequest):
    TEMPLATE_PATH = settings.saml.artifactresolve_request_template

    def __init__(self, artifact_code) -> None:
        super().__init__()
        self.template = etree.parse(self.TEMPLATE_PATH).getroot()
        self.root = self.template.find('.//samlp:ArtifactResolve', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})

        self._add_root_id(self.root)
        self._add_root_issue_instant(self.root)
        self._add_reference()
        self._add_certs()
        self._add_artifact(artifact_code)
        self._sign(self.root)

    def _add_artifact(self, artifact_code):
        artifact = self.root.find('.//samlp:Artifact', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})
        artifact.text = artifact_code

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)

if __name__ == "__main__":
    test = AuthNRequest()
    print(test.get_xml().decode())
    print(test.get_base64_string().decode())

    test = ArtifactResolveRequest("AAQAAC++9v4UQ3mOG7AEGSVSddlO0YmaRCGk1jkVRoStga0sICMv4wAAAAA=")
    print(test.get_xml().decode())
    print(test.get_base64_string().decode())