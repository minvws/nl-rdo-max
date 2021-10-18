# pylint: disable=c-extension-no-member
import base64
import secrets

from abc import abstractmethod
from typing import Optional, Any, Tuple
from datetime import datetime

import xmlsec
from lxml import etree

from inge6.saml.utils import read_cert

from .constants import ROOT_DIR


def get_issue_instant():
    return datetime.utcnow().isoformat().split('.')[0] + 'Z',

def add_root_issue_instant(root) -> None:
    root.attrib['IssueInstant'] = get_issue_instant()

def add_root_id(root, id_hash: str) -> None:
    root.attrib['ID'] = id_hash

def add_reference(root, id_hash: str) -> None:
    reference_node: Optional[Any] = xmlsec.tree.find_node(root, xmlsec.constants.NodeReference)
    if reference_node is None:
        raise ValueError("Reference node not found, cannot set URI in reference node of signature element.")
    reference_node.attrib['URI'] = f"#{id_hash}"

def add_certs(root, cert_path: str) -> None:
    cert_node = root.find('.//ds:X509Certificate', {'ds': 'http://www.w3.org/2000/09/xmldsig#'})

    with open(cert_path, 'r', encoding='utf-8') as cert_file:
        cert_node.text = base64.b64encode(cert_file.read().encode())

def add_issuer(root, issuer_id):
    root.find('./saml:Issuer', {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}).text = issuer_id

def add_destination(root, destination):
    root.attrib['Destination'] = destination

def sign(root, key_path):
    with open(key_path, 'r', encoding='utf-8') as key_file:
        key_data = key_file.read()

    signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_memory(key_data, xmlsec.constants.KeyDataFormatPem)
    ctx.key = key
    ctx.register_id(root)
    ctx.sign(signature_node)

def add_artifact(root, artifact_code) -> None:
    artifact = root.find('.//samlp:Artifact', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})
    artifact.text = artifact_code

class SAMLRequest:

    def __init__(self, keypair_sign: Tuple[str, str]) -> None:
        """
        Initiate a SAMLRequest with a parsed xml tree and keypair for signing

        :param root: parsed XML tree
        :param keypair: (cert_path, key_path) tuple for signing of the messages.
        """
        self._id_hash = "_" + secrets.token_hex(41) # total length 42.
        self.signing_cert_path = keypair_sign[0]
        self.signing_key_path = keypair_sign[1]

    def get_xml(self, xml_declaration: bool = False) -> bytes:
        if xml_declaration:
            return etree.tostring(self.root, xml_declaration=True, encoding='UTF-8')
        return etree.tostring(self.root)

    def get_base64_string(self) -> bytes:
        return base64.b64encode(self.get_xml())

    @property
    @abstractmethod
    def root(self):
        pass

    @property
    def saml_elem(self):
        return self.root

    def sign(self, node, id_hash: str):
        def add_reference(root, id_hash: str) -> None:
            reference_node: Optional[Any] = xmlsec.tree.find_node(root, xmlsec.constants.NodeReference)
            if reference_node is None:
                raise ValueError("Reference node not found, cannot set URI in reference node of signature element.")
            reference_node.attrib['URI'] = f"#{id_hash}"

        with open(self.signing_key_path, 'r', encoding='utf-8') as key_file:
            key_data = key_file.read()

        add_reference(node, id_hash=id_hash)

        signature_node = xmlsec.tree.find_node(node, xmlsec.constants.NodeSignature)
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_memory(key_data, xmlsec.constants.KeyDataFormatPem)
        ctx.key = key
        ctx.register_id(node)
        ctx.sign(signature_node)

        return node

class AuthNRequest(SAMLRequest):
    """
    Creates an AuthnRequest based on an Authn request template.
    """
    TEMPLATE_PATH = 'authn_request.xml.jinja'

    def __init__(self, sso_url, issuer_id, keypair, jinja_env) -> None:
        super().__init__(keypair)

        self.jinja_env = jinja_env
        self.sso_url = sso_url
        self.issuer_id = issuer_id
        self.keypair = keypair

        self._root = self.render()

    def render(self):
        template = self.jinja_env.get_template(self.TEMPLATE_PATH)
        raw_request = template.render({
            'ID': self._id_hash,
            'destination': self.sso_url,
            'issuer_id': self.issuer_id,
            'issue_instant': get_issue_instant(),
            'sign_cert': read_cert(self.signing_cert_path),
            'force_authn': "false"
        })

        xml_request = etree.parse(raw_request).getroot()
        return self.sign(xml_request, self._id_hash)

    @property
    def root(self):
        return self._root

class ArtifactResolveRequest(SAMLRequest):
    """
    Creates an ArtifactResolveRequest based on an Artifact resolve template.
    """
    TEMPLATE_PATH = 'artifactresolve_request.xml.jinja'

    def __init__(self, artifact_code, sso_url, issuer_id, keypair, jinja_env) -> None:
        super().__init__(keypair)

        self.jinja_env = jinja_env
        self.sso_url = sso_url
        self.issuer_id = issuer_id
        self.keypair = keypair
        self.artifact = artifact_code

        self.saml_resolve_req = self.render()
        self._root = self.to_soap_envelope(self.saml_resolve_req)

    def render(self):
        template = self.jinja_env.get_template(self.TEMPLATE_PATH)
        raw_request = template.render({
            'ID': self._id_hash,
            'destination': self.sso_url,
            'issuer_id': self.issuer_id,
            'issue_instant': get_issue_instant(),
            'sign_cert': read_cert(self.signing_cert_path),
            'artifact': self.artifact
        })
        xml_request = etree.fromstring(raw_request).getroot()
        return self.sign(xml_request, self._id_hash)

    def to_soap_envelope(self, node):
        return f"""<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
    <SOAP-ENV:Body>
        {node}
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""

    @property
    def saml_elem(self):
        return self.saml_resolve_req

    @property
    def root(self):
        return self._root
