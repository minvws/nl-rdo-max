import pytest
# pylint: disable=c-extension-no-member
import xmlsec

from inge6.saml import AuthNRequest, ArtifactResolveRequest
from inge6.saml.metadata import SPMetadata

SETTINGS_DICT = {
    "strict": True,
    "debug": True,
    "sp": {
        "entityId": "https://localhost:8007",
        "assertionConsumerService": {
            "url": "https://tvs.acc.coronacheck.nl/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
        },
        "attributeConsumingService": {
            "serviceName": "CoronaCheck",
            "serviceDescription": "Test vaccinatie bewijzen inlogservice",
            "requestedAttributes": [
                {
                    "index": 1,
                    "name": "urn:nl-eid-gdi:1.0:ServiceUUID",
                    "isRequired": True,
                    "attributeValue": ["c282ff81-005f-86cb-e053-0c069d0ae01a"]
                }
            ]
        }
    },
    "idp": {
        "entityId": "https://was-preprod1.digid.nl/saml/idp/metadata",
        "singleSignOnService": {
            "url": "https://preprod1.digid.nl/saml/idp/request_authentication",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "<onelogin_connector_cert>"
    }
}

keypair_path = ('saml/tvs/certs/sp.crt', 'saml/tvs/certs/sp.key')

def test_artifact_value():
    expected = "some_artifact_code"
    saml_req = ArtifactResolveRequest(expected, sso_url='test_url', issuer_id='test_id', keypair=keypair_path)
    artifact_node = saml_req.root.find('.//samlp:Artifact', {'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol'})

    assert artifact_node.text == expected

@pytest.mark.parametrize("saml_request", [
    AuthNRequest(sso_url='test_url', issuer_id='test_id', keypair=keypair_path),
    ArtifactResolveRequest('some_artifact_code', sso_url='test_url', issuer_id='test_id', keypair=keypair_path),
    SPMetadata(SETTINGS_DICT, keypair_path)])
def test_verify_requests(saml_request): # pylint: disable=unused-argument
    getroot =saml_request.saml_elem
    # xmlsec.tree.add_ids(getroot, ["ID"])
    signature_node = xmlsec.tree.find_node(getroot, xmlsec.constants.NodeSignature)
    # Create a digital signature context (no key manager is needed).
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_file(keypair_path[0], xmlsec.constants.KeyDataFormatCertPem)
    # Set the key on the context.
    ctx.key = key
    ctx.register_id(getroot)
    ctx.verify(signature_node)
    assert True
