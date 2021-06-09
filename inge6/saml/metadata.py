# pylint: disable=c-extension-no-member
import json

from typing import Dict, Optional

from lxml import etree
import xmlsec

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

from .saml_request import (
    SAMLRequest, add_root_id,
    add_reference, sign,
)
from .constants import NAMESPACES
from .utils import get_loc_bind, has_valid_signatures
from ..config import settings


def add_certs(root, cert_data: str) -> None:
    certifi_elems = root.findall('.//ds:X509Certificate', NAMESPACES)

    for elem in certifi_elems:
        elem.text = cert_data.replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----\n", "")


class SPMetadata(SAMLRequest):
    TEMPLATE_PATH = settings.saml.sp_template
    SETTINGS_PATH = 'saml/settings.json'

    DEFAULT_SLS = settings.issuer + '/sls'
    DEFAULT_ACS = settings.issuer + '/acs'

    def __init__(self) -> None:
        super().__init__(etree.parse(self.TEMPLATE_PATH).getroot())

        with open(self.SETTINGS_PATH, 'r') as settings_file:
            self.settings_dict = json.loads(settings_file.read())

        with open(self.CERT_PATH, 'r') as cert_file:
            self.cert_data = cert_file.read()

        add_root_id(self.root, self._id_hash)
        add_reference(self.root, self._id_hash)
        add_certs(self.root, self.cert_data)

        self._add_service_locs()
        self._add_attribute_value()
        self._add_keynames()
        self._add_prefix_service_desc()

        sign(self.root, self.KEY_PATH)

    def _add_keynames(self) -> None:
        cert = load_certificate(FILETYPE_PEM, self.cert_data)
        sha256_fingerprint = cert.digest("sha256").decode().replace(":", "").lower()
        keyname_elems = self.root.findall('.//ds:KeyInfo/ds:KeyName', NAMESPACES)
        for keyname_elem in keyname_elems:
            keyname_elem.text = sha256_fingerprint

    def _add_service_locs(self) -> None:
        sls_elem = self.root.find('.//md:SingleLogoutService', NAMESPACES)
        acs_elem = self.root.find('.//md:AssertionConsumerService', NAMESPACES)

        sls_loc = self._from_settings('sp.SingleLogoutService.url', self.DEFAULT_SLS)
        acs_loc = self._from_settings('sp.assertionConsumerService.url', self.DEFAULT_ACS)

        sls_elem.attrib['Location'] = sls_loc
        acs_elem.attrib['Location'] = acs_loc

    def _from_settings(self, selector: str, default: Optional[str] = None) -> Optional[str]:
        key_hierarchy = selector.split('.')
        value = self.settings_dict
        for key in key_hierarchy:
            try:
                value = value[key]
            except KeyError as _:
                return default
        return value

    def _add_attribute_value(self) -> None:
        attr_value_elem = self.root.find('.//md:AttributeConsumingService//saml:AttributeValue', NAMESPACES)

        try:
            attr_value_elem.text = self.settings_dict['sp']['attributeConsumingService']['requestedAttributes'][0]['attributeValue'][0]
        except KeyError as key_error:
            raise KeyError('key does not exist. please check your settings.json') from key_error

    def _valid_signature(self) -> bool:
        _, is_valid = has_valid_signatures(self.root, cert_data=self.cert_data)
        return is_valid

    def _contains_keyname(self):
        return self.root.find('.//ds:KeyInfo/ds:KeyName', NAMESPACES) is not None

    def _has_correct_bindings(self) -> bool:
        correct_bindings = True
        sls_elem = self.root.find('.//md:SingleLogoutService', NAMESPACES)
        acs_elem = self.root.find('.//md:AssertionConsumerService', NAMESPACES)

        if sls_elem is not None:
            correct_bindings = correct_bindings and sls_elem.attrib['Binding'] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

        # Required element.
        correct_bindings = correct_bindings and acs_elem.attrib['Binding'] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

        return correct_bindings

    def _add_prefix_service_desc(self) -> None:
        service_desc_elem = self.root.find('.//md:ServiceDescription', NAMESPACES)
        service_desc_elem.text = settings.environment.capitalize() + ' ' + service_desc_elem.text

    def validate(self) -> list:
        errors = []

        if self.root.tag != '{%s}EntityDescriptor' % NAMESPACES['md']:
            errors.append('Root is not an EntityDescriptor')

        if len(self.root.findall('.//md:SPSSODescriptor', NAMESPACES)) != 1:
            errors.append('Only one SPSSO Descriptor allowed')

        if not self._has_correct_bindings():
            errors.append('Incorrect bindings for SPSSO services')

        if not self._contains_keyname():
            errors.append('Does not contain a keyname in KeyDescriptor')

        if not self._valid_signature():
            errors.append('Invalid Signature')

        return errors

class IdPMetadata:
    IDP_PATH = settings.saml.idp_path

    def __init__(self) -> None:
        self.template = etree.parse(self.IDP_PATH).getroot()
        new_root, valid_sign = has_valid_signatures(self.template, cert_data=self.get_cert_pem_data())
        if not valid_sign:
            raise xmlsec.VerificationError("Signature is invalid")
        self.template = new_root

    def _validate_md(self) -> bool:
        raise NotImplementedError("WIP")

    def find_in_md(self, name: str):
        return self.template.find(f'.//md:{name}', {'md': "urn:oasis:names:tc:SAML:2.0:metadata"})

    def get_artifact_rs(self) -> Dict[str, str]:
        resolution_service = self.find_in_md('ArtifactResolutionService')
        return get_loc_bind(resolution_service)

    def get_cert_pem_data(self) -> str:
        return f"""-----BEGIN CERTIFICATE-----\n{self.template.find('.//md:IDPSSODescriptor//dsig:X509Certificate', NAMESPACES).text}-----END CERTIFICATE-----"""

    def get_sso(self) -> Dict[str, str]:
        sso = self.find_in_md('SingleSignOnService')
        return get_loc_bind(sso)

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)
