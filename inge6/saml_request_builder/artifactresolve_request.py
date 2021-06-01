from lxml import etree

from ..config import settings
from .saml_request import SamlRequest


class ArtifactResolveRequest(SamlRequest):
    TEMPLATE_PATH = settings.saml.artifactresolve_request_template
    # TEMPLATE_PATH = '../saml/templates/xml/artifactresolve_request.xml'

    def __init__(self, artifact_code) -> None:
        super().__init__()
        self.template = etree.parse(self.TEMPLATE_PATH).getroot()
        self.root = self.root.find('.//samlp:ArtifactResolve', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})

        self._add_root_id(self.root)
        self._add_root_issue_instant(self.root)
        self._add_reference()
        self._add_certs()
        self._add_artifact(artifact_code)
        self._sign(self.root)

    def _add_artifact(self, artifact_code):
        artifact = self.root.find('.//samlp:Artifact', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})
        artifact.text = artifact_code


if __name__ == "__main__":
    test = ArtifactResolveRequest("AAQAAC++9v4UQ3mOG7AEGSVSddlO0YmaRCGk1jkVRoStga0sICMv4wAAAAA=")
    print(test.get_xml().decode())
    print(test.get_base64_string().decode())