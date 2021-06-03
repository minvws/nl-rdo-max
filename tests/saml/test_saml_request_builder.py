import pytest
import xmlsec
from lxml import etree

from inge6.saml import AuthNRequest, ArtifactResolveRequest, SPMetadata


def test_artifact_value():
    expected = "some_artifact_code"
    saml_req = ArtifactResolveRequest(expected)
    artifact_node = saml_req.root.find('.//samlp:Artifact', {'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'})

    assert artifact_node.text == expected

@pytest.mark.parametrize("saml_request", [
    AuthNRequest(),
    ArtifactResolveRequest('some_artifact_code'),
    SPMetadata()])
def test_verify_requests(saml_request):
    getroot =saml_request.root
    # xmlsec.tree.add_ids(getroot, ["ID"])
    signature_node = xmlsec.tree.find_node(getroot, xmlsec.constants.NodeSignature)
    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file('saml/certs/mycert.pem', xmlsec.constants.KeyDataFormatCertPem)
    # Set the key on the context.
    ctx.key = key
    ctx.register_id(getroot)
    ctx.verify(signature_node)
    assert True
