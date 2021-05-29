from lxml import etree
import secrets

from ..config import settings
from .saml_request import SamlRequest


class ArtifactResolveRequest(SamlRequest):
    TEMPLATE_PATH = settings.saml.artifactresolve_request_template

    def __init__(self, artifact_code) -> None:
        super().__init__()
        self.template = etree.parse(self.TEMPLATE_PATH).getroot()

        self._add_root_id(self.template)
        self._add_reference()
        self._add_certs()
        self._add_artifact(artifact_code)
        self._sign()

    def _add_artifact(self, artifact_code):
        artifact = self.template.find('.//samlp:Artifact', {'samlp': "urn:oasis:names:tc:SAML:2.0:protocol"})
        artifact.text = artifact_code


if __name__ == "__main__":
    test = ArtifactResolveRequest("AAQAAC++9v4UQ3mOG7AEGSVSddlO0YmaRCGk1jkVRoStga0sICMv4wAAAAA=")
    print(test.get_xml().decode())
    print(test.get_base64_string().decode())