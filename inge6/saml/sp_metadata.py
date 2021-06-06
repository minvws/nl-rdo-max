# pylint: disable=c-extension-no-member
import base64
import json

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

from lxml import etree

from .saml_request import (
    SAMLRequest, add_root_id,
    add_reference, sign,
)
from .constants import NAMESPACES
from .utils import has_valid_signature
from ..config import settings


def add_certs(root, cert_data):
    certifi_elems = root.findall('.//ds:X509Certificate', NAMESPACES)

    for elem in certifi_elems:
        elem.text = "\n".join(cert_data.split('\n')[1:-1])

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
        self._add_keyname()
        self._add_prefix_service_desc()

        sign(self.root, self.KEY_PATH)

    def _add_keyname(self):
        cert = load_certificate(FILETYPE_PEM, self.cert_data)
        sha1_fingerprint = cert.digest("sha256").upper()
        keyname_elem = self.root.find('.//ds:KeyInfo/ds:KeyName', NAMESPACES)
        keyname_elem.text = sha1_fingerprint

    def _add_service_locs(self):
        sls_elem = self.root.find('.//md:SingleLogoutService', NAMESPACES)
        acs_elem = self.root.find('.//md:AssertionConsumerService', NAMESPACES)

        sls_loc = self._from_settings('sp.SingleLogoutService.url', self.DEFAULT_SLS)
        acs_loc = self._from_settings('sp.assertionConsumerService.url', self.DEFAULT_ACS)

        sls_elem.attrib['Location'] = sls_loc
        acs_elem.attrib['Location'] = acs_loc

    def _from_settings(self, selector, default = None):
        key_hierarchy = selector.split('.')
        value = self.settings_dict
        for key in key_hierarchy:
            try:
                value = value[key]
            except KeyError as _:
                return default
        return value

    def _add_attribute_value(self):
        attr_value_elem = self.root.find('.//md:AttributeConsumingService//saml:AttributeValue', NAMESPACES)

        try:
            attr_value_elem.text = self.settings_dict['sp']['attributeConsumingService']['requestedAttributes'][0]['attributeValue'][0]
        except KeyError as key_error:
            raise KeyError('key does not exist. please check your settings.json') from key_error

    def _valid_signature(self):
        return has_valid_signature(self.root)

    def _contains_keyname(self):
        return self.root.find('.//ds:KeyInfo/ds:KeyName', NAMESPACES) is not None

    def _has_correct_bindings(self):
        correct_bindings = True
        sls_elem = self.root.find('.//md:SingleLogoutService', NAMESPACES)
        acs_elem = self.root.find('.//md:AssertionConsumerService', NAMESPACES)

        if sls_elem is not None:
            correct_bindings = correct_bindings and sls_elem.attrib['Binding'] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

        # Required element.
        correct_bindings = correct_bindings and acs_elem.attrib['Binding'] == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

        return correct_bindings

    def _add_prefix_service_desc(self):
        service_desc_elem = self.root.find('.//md:ServiceDescription', NAMESPACES)
        service_desc_elem.text = settings.environment.capitalize() + ' ' + service_desc_elem.text

    def validate(self):
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

sp_metadata = SPMetadata()
