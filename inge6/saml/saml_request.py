# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
# pylint: disable=c-extension-no-member
import base64
import secrets
from typing import Optional, Any
from datetime import datetime

import xmlsec
from lxml import etree

from ..config import settings

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

    with open(cert_path, 'r') as cert_file:
        cert_node.text = base64.b64encode(cert_file.read().encode())

def add_issuer(root, issuer_id):
    root.find('./saml:Issuer', {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}).text = issuer_id

def add_destination(root, destination):
    root.attrib['Destination'] = destination

def sign(root, key_path):
    signature_node = xmlsec.tree.find_node(root, xmlsec.constants.NodeSignature)
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file(key_path, xmlsec.constants.KeyDataFormatPem)
    ctx.key = key
    ctx.register_id(root)
    ctx.sign(signature_node)

def add_artifact(root, artifact_code) -> None:
    artifact = root.find('.//samlp:Artifact', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})
    artifact.text = artifact_code

class SAMLRequest:
    KEY_PATH = settings.saml.key_path
    CERT_PATH = settings.saml.cert_path

    def __init__(self, root) -> None:
        self._id_hash = "_" + secrets.token_hex(41) # total length 42.
        self.root = root

    def get_xml(self) -> bytes:
        return etree.tostring(self.root)

    def get_base64_string(self) -> bytes:
        return base64.b64encode(self.get_xml())

    @property
    def saml_elem(self):
        return self.root

class AuthNRequest(SAMLRequest):
    TEMPLATE_PATH = settings.saml.authn_request_template

    def __init__(self, sso_url, issuer_id) -> None:
        super().__init__(etree.parse(self.TEMPLATE_PATH).getroot())
        add_root_id(self.root, self._id_hash)
        add_destination(self.root, sso_url)
        add_issuer(self.root, issuer_id)
        add_root_issue_instant(self.root)
        add_reference(self.root, self._id_hash)
        add_certs(self.root, self.CERT_PATH)
        sign(self.root, self.KEY_PATH)

class ArtifactResolveRequest(SAMLRequest):
    TEMPLATE_PATH = settings.saml.artifactresolve_request_template

    def __init__(self, artifact_code, sso_url, issuer_id) -> None:
        super().__init__(etree.parse(self.TEMPLATE_PATH).getroot())
        self.saml_resolve_req = self.root.find('.//samlp:ArtifactResolve', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})

        add_root_id(self.saml_resolve_req, self._id_hash)
        add_root_issue_instant(self.saml_resolve_req)
        add_destination(self.saml_resolve_req, sso_url)
        add_issuer(self.saml_resolve_req, issuer_id)
        add_reference(self.saml_resolve_req, self._id_hash)
        add_certs(self.saml_resolve_req, self.CERT_PATH)
        add_artifact(self.saml_resolve_req, artifact_code)
        sign(self.saml_resolve_req, self.KEY_PATH)

    @property
    def saml_elem(self):
        return self.saml_resolve_req
