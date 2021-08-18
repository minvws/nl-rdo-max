# pylint: disable=c-extension-no-member

import pytest
import xmlsec

from inge6.saml import AuthNRequest, ArtifactResolveRequest
from inge6.saml.metadata import SPMetadata
from inge6.config import settings


def test_artifact_value():
    expected = "some_artifact_code"
    saml_req = ArtifactResolveRequest(expected, sso_url='test_url', issuer_id='test_id')
    artifact_node = saml_req.root.find('.//samlp:Artifact', {'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'})

    assert artifact_node.text == expected

@pytest.mark.parametrize("saml_request", [
    AuthNRequest(sso_url='test_url', issuer_id='test_id'),
    ArtifactResolveRequest('some_artifact_code', sso_url='test_url', issuer_id='test_id'),
    SPMetadata()])
def test_verify_requests(saml_request): # pylint: disable=unused-argument
    getroot =saml_request.saml_elem
    # xmlsec.tree.add_ids(getroot, ["ID"])
    signature_node = xmlsec.tree.find_node(getroot, xmlsec.constants.NodeSignature)
    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file(settings.saml.cert_path, xmlsec.constants.KeyDataFormatCertPem)
    # Set the key on the context.
    ctx.key = key
    ctx.register_id(getroot)
    ctx.verify(signature_node)
    assert True
