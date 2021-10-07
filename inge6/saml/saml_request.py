# pylint: disable=c-extension-no-member
from abc import abstractmethod
import base64
import secrets
from typing import Optional, Any, Tuple
from datetime import datetime

import xmlsec
from lxml import etree

from inge6.saml.constants import NAMESPACES
from inge6.saml.utils import strip_cert

from ..config import get_settings

def add_root_issue_instant(root) -> None:
    root.attrib['IssueInstant'] = datetime.utcnow().isoformat().split('.')[0] + 'Z'

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

    root.find('.//ds:Signature/ds:KeyInfo//ds:X509Certificate', NAMESPACES).text = strip_cert(key_data)

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

class AuthNRequest(SAMLRequest):
    """
    Creates an AuthnRequest based on an Authn request template.

    Required settings:
        - settings.saml.authn_request_template, path to authn request template
    """
    TEMPLATE_PATH = get_settings().saml.authn_request_template

    def __init__(self, sso_url, issuer_id, keypair) -> None:
        super().__init__(keypair)
        self._root = etree.parse(self.TEMPLATE_PATH).getroot()

        add_root_id(self.root, self._id_hash)
        add_destination(self.root, sso_url)
        add_issuer(self.root, issuer_id)
        add_root_issue_instant(self.root)
        add_reference(self.root, self._id_hash)
        add_certs(self.root, self.signing_cert_path)
        sign(self.root, self.signing_key_path)

    @property
    def root(self):
        return self._root

class ArtifactResolveRequest(SAMLRequest):
    """
    Creates an ArtifactResolveRequest based on an Artifact resolve template.

    Required settings:
        - settings.saml.artifactresolve_request_template, path to artifact resolve request template
    """
    TEMPLATE_PATH = get_settings().saml.artifactresolve_request_template

    def __init__(self, artifact_code, sso_url, issuer_id, keypair) -> None:
        super().__init__(keypair)
        self._root = etree.parse(self.TEMPLATE_PATH).getroot()
        self.saml_resolve_req = self.root.find('.//samlp:ArtifactResolve', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})

        add_root_id(self.saml_resolve_req, self._id_hash)
        add_root_issue_instant(self.saml_resolve_req)
        add_destination(self.saml_resolve_req, sso_url)
        add_issuer(self.saml_resolve_req, issuer_id)
        add_reference(self.saml_resolve_req, self._id_hash)
        add_certs(self.saml_resolve_req, self.signing_cert_path)
        add_artifact(self.saml_resolve_req, artifact_code)
        sign(self.saml_resolve_req, self.signing_key_path)

    @property
    def saml_elem(self):
        return self.saml_resolve_req

    @property
    def root(self):
        return self._root
