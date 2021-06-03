from lxml import etree

from ..config import settings

class IdPMetadataParser:
    IDP_PATH = settings.saml.idp_path
    # IDP_PATH = "../saml/metadata/idp_metadata.xml"

    def __init__(self) -> None:
        self.template = etree.parse(self.IDP_PATH).getroot()

    def _validate_md():
        raise NotImplementedError("WIP")

    def find_in_md(self, name):
        return self.template.find(f'.//md:{name}', {'md': "urn:oasis:names:tc:SAML:2.0:metadata"})

    def _get_loc_bind(self, element):
        location = element.get('Location')
        binding = element.get('Binding')
        return {
            'location': location,
            'binding': binding
        }

    def get_artifact_rs(self):
        resolution_service = self.find_in_md('ArtifactResolutionService')
        return self._get_loc_bind(resolution_service)

    def get_sso(self):
        sso = self.find_in_md('SingleSignOnService')
        return self._get_loc_bind(sso)

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)

if __name__ == "__main__":
    idp_metadata = IdPMetadataParser()
    # print(idp_metadata.get_xml())
    print(idp_metadata.get_artifact_rs())
    print(idp_metadata.get_sso())