# pylint: disable=c-extension-no-member
from lxml import etree
import xmlsec

from .utils import get_loc_bind, has_valid_signatures
from .constants import NAMESPACES
from ..config import settings

class IdPMetadataParser:
    IDP_PATH = settings.saml.idp_path

    def __init__(self) -> None:
        self.template = etree.parse(self.IDP_PATH).getroot()
        new_root, valid_sign = has_valid_signatures(self.template, cert_data=self.get_cert_pem_data())
        if not valid_sign:
            raise xmlsec.VerificationError("Signature is invalid")
        self.template = new_root

    def _validate_md(self):
        raise NotImplementedError("WIP")

    def find_in_md(self, name):
        return self.template.find(f'.//md:{name}', {'md': "urn:oasis:names:tc:SAML:2.0:metadata"})

    def get_artifact_rs(self):
        resolution_service = self.find_in_md('ArtifactResolutionService')
        return get_loc_bind(resolution_service)

    def get_cert_pem_data(self):
        return f"""-----BEGIN CERTIFICATE-----\n{self.template.find('.//md:IDPSSODescriptor//dsig:X509Certificate', NAMESPACES).text}-----END CERTIFICATE-----"""

    def get_sso(self):
        sso = self.find_in_md('SingleSignOnService')
        return get_loc_bind(sso)

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)

idp_metadata = IdPMetadataParser()
