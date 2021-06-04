# pylint: disable=c-extension-no-member
from lxml import etree

from .utils import get_loc_bind
from ..config import settings

class IdPMetadataParser:
    IDP_PATH = settings.saml.idp_path
    # IDP_PATH = "../saml/metadata/idp_metadata.xml"

    def __init__(self) -> None:
        self.template = etree.parse(self.IDP_PATH).getroot()

    def _validate_md(self):
        raise NotImplementedError("WIP")

    def find_in_md(self, name):
        return self.template.find(f'.//md:{name}', {'md': "urn:oasis:names:tc:SAML:2.0:metadata"})

    def get_artifact_rs(self):
        resolution_service = self.find_in_md('ArtifactResolutionService')
        return get_loc_bind(resolution_service)

    def get_sso(self):
        sso = self.find_in_md('SingleSignOnService')
        return get_loc_bind(sso)

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)

idp_metadata = IdPMetadataParser()
