# pylint: disable=c-extension-no-member
from typing import Dict, Optional
import textwrap

from lxml import etree
import xmlsec

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

from .saml_request import (
    SAMLRequest, add_root_id,
    add_reference, sign,
)
from .constants import NAMESPACES
from .utils import get_loc_bind, has_valid_signatures, from_settings
from ..config import settings

def _enforce_cert_newlines(cert_data):
    return "\n".join(textwrap.wrap(cert_data.replace('\n', ''), 64))

def _strip_cert(cert_data):
    return "\n".join(cert_data.strip().split('\n')[1:-1])

def add_cert(root, cert_data: str, key_descriptor_use: str) -> None:
    stripped_cert = _strip_cert(cert_data)
    certifi_elem = root.find(f'.//md:KeyDescriptor[@use="{key_descriptor_use}"]//ds:X509Certificate', NAMESPACES)
    certifi_elem.text = stripped_cert

def add_enc_pubkey(root, cert_data: str) -> None:
    add_cert(root, cert_data, 'encryption')

def add_signing_pubkey(root, cert_data: str) -> None:
    add_cert(root, cert_data, 'signing')


class SPMetadata(SAMLRequest):
    """
    Ability to generate metadata needed for IDPs. It uses the template defined in the template path.

    Required settings:
        - settings.saml.sp_template, path to the sp metadata template
        - settings.issuer, name of the issuer
    """
    TEMPLATE_PATH = settings.saml.sp_template


    def __init__(self, settings_dict, keypair_sign, idp_name, enc_pubkey = None) -> None:
        """
        Initialize SPMetadata using the settings in the settings dict, for idp_name. And sign it
        using the keypair_sign, which is also the pair used for receiving encrypted material.

        :param settings_dict: dictionary containing the settings for the SP
        :param keypair_sign: paths to the private and public key for signing and signature validation
        :param idp_name: Identity Provider this service provider metadata is configured for.
        :param pubkey_enc: (OPTIONAL) path to the public key the IdP should use for XML encryption, useful when
        decryption of the messages is done by another party. Otherwise, same key as for signing is used.
        """
        super().__init__(etree.parse(self.TEMPLATE_PATH).getroot(), keypair_sign)
        self.default_acs_url = f'https://{idp_name}.{settings.issuer}/acs'
        self.default_acs_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

        self.settings_dict = settings_dict
        self.issuer_id = self.settings_dict['sp']['entityId']

        self.enc_pubkey = None
        if enc_pubkey is not None:
            with open(enc_pubkey, 'r', encoding='utf-8') as enc_pubkey_file:
                self.enc_pubkey = enc_pubkey_file.read()

        with open(self.signing_cert_path, 'r', encoding='utf-8') as signing_cert_file:
            self.signing_cert = signing_cert_file.read()

        self.keyname: Optional[str] = None
        self.entity_id: Optional[str] = None

        add_root_id(self.root, self._id_hash)
        add_reference(self.root, self._id_hash)

        self._add_certs()
        self._add_entity_id()
        self._add_service_details()
        self._add_attribute_value()
        self._add_keynames()

        sign(self.root, self.signing_key_path)

    def _add_certs(self) -> None:
        add_signing_pubkey(self.root, self.signing_cert)
        if self.enc_pubkey is None:
            add_enc_pubkey(self.root, self.signing_cert)
        else:
            add_enc_pubkey(self.root, self.enc_pubkey)

    def _add_entity_id(self) -> None:
        self.entity_id = from_settings(self.settings_dict, 'sp.entityId')
        if self.entity_id is None:
            raise ValueError('Please specify the sp.entityId attribute in settings.json')
        self.root.attrib['entityID'] = self.entity_id

    def _add_keynames(self) -> None:
        cert = load_certificate(FILETYPE_PEM, self.signing_cert)
        sha256_fingerprint = cert.digest("sha256").decode().replace(":", "").lower()
        self.keyname = sha256_fingerprint

        keyname_elems = self.root.findall('.//ds:KeyInfo/ds:KeyName', NAMESPACES)
        for keyname_elem in keyname_elems:
            keyname_elem.text = sha256_fingerprint

    def _add_service_details(self) -> None:
        acs_elem = self.root.find('.//md:AssertionConsumerService', NAMESPACES)

        acs_binding = from_settings(self.settings_dict, 'sp.assertionConsumerService.binding', self.default_acs_url)
        acs_loc = from_settings(self.settings_dict, 'sp.assertionConsumerService.url', self.default_acs_binding)

        acs_elem.attrib['Location'] = acs_loc
        acs_elem.attrib['Binding'] = acs_binding

        attr_consuming_service = self.root.find('.//md:AttributeConsumingService', NAMESPACES)
        service_name = attr_consuming_service.find('./md:ServiceName', NAMESPACES)
        service_desc = attr_consuming_service.find('./md:ServiceDescription', NAMESPACES)

        service_name.text = from_settings(self.settings_dict, 'sp.attributeConsumingService.serviceName', 'CoronaCheck')
        service_desc.text = from_settings(self.settings_dict, 'sp.attributeConsumingService.serviceDescription', 'CoronaCheck Inlogservice')

    def _add_attribute_value(self) -> None:
        attr_value_elem = self.root.find('.//md:AttributeConsumingService//saml:AttributeValue', NAMESPACES)

        try:
            attr_value_elem.text = self.settings_dict['sp']['attributeConsumingService']['requestedAttributes'][0]['attributeValue'][0]
        except KeyError as key_error:
            raise KeyError('key does not exist. please check your settings.json') from key_error

    def _valid_signature(self) -> bool:
        _, is_valid = has_valid_signatures(self.root, cert_data=self.signing_cert)
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

    def __init__(self, idp_metadata_path) -> None:
        self.template = etree.parse(idp_metadata_path).getroot()
        new_root, valid_sign = has_valid_signatures(self.template, cert_data=self.get_cert_pem_data())
        if not valid_sign:
            raise xmlsec.VerificationError("Signature is invalid")
        self.template = new_root

        self.entity_id = self.template.attrib['entityID']
        self.keyname = self.template.find('.//md:IDPSSODescriptor//dsig:KeyName', NAMESPACES).text

    def find_in_md(self, name: str):
        return self.template.find(f'.//md:{name}', {'md': "urn:oasis:names:tc:SAML:2.0:metadata"})

    def get_artifact_rs(self) -> Dict[str, str]:
        resolution_service = self.find_in_md('ArtifactResolutionService')
        return get_loc_bind(resolution_service)

    def get_cert_pem_data(self) -> str:
        cert_data = self.template.find('.//md:IDPSSODescriptor//dsig:X509Certificate', NAMESPACES).text
        cert_data = _enforce_cert_newlines(cert_data)
        return f"""-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"""

    def get_sso(self, binding='POST') -> Dict[str, str]:
        sso = self.template.find(
            f".//md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-{binding}']",
            {'md': "urn:oasis:names:tc:SAML:2.0:metadata"}
        )
        return get_loc_bind(sso)

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)
