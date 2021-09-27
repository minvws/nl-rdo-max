# pylint: disable=c-extension-no-member
import json

from typing import Dict, Optional
import secrets

from lxml import etree
import xmlsec

from .saml_request import SAMLRequest, add_reference, sign
from .constants import NAMESPACES
from .utils import get_loc_bind, has_valid_signatures, from_settings, compute_keyname, strip_cert, enforce_cert_newlines


class SPMetadata(SAMLRequest):
    """
    Ability to generate metadata needed for IDPs. It uses the template defined in the template path.

    Required settings:
        - settings.saml.sp_template, path to the sp metadata template
        - settings.issuer, name of the issuer
    """
    TEMPLATE_NAME = 'sp_metadata.xml.jinja'
    CLUSTER_TEMPLATE_NAME = 'sp_metadata.clustered.xml.jinja'


    def __init__(self, settings_dict, keypair_sign, jinja_env) -> None:
        """
        Initialize SPMetadata using the settings in the settings dict, for idp_name. And sign it
        using the keypair_sign, which is also the pair used for receiving encrypted material.

        :param settings_dict: dictionary containing the settings for the SP
        :param keypair_sign: paths to the private and public key for signing and signature validation
        :param idp_name: Identity Provider this service provider metadata is configured for.
        :param pubkey_enc: (OPTIONAL) path to the public key the IdP should use for XML encryption, useful when
        decryption of the messages is done by another party. Otherwise, same key as for signing is used.
        """
        super().__init__(keypair_sign)

        self.jinja_env = jinja_env
        self.settings_dict = settings_dict

        self.dv_keynames = []

        self.cluster_settings = None
        if 'clustered' in settings_dict and settings_dict['clustered'] != "":
            with open(settings_dict['clustered'], 'r', encoding='utf-8') as cluster_settings_file:
                self.cluster_settings = json.loads(cluster_settings_file.read())

        self._root = etree.fromstring(self.render_template())
        add_reference(self.root, self._id_hash)
        sign(self.root, self.signing_key_path)

    @property
    def root(self):
        return self._root

    @property
    def entity_id(self):
        return from_settings(self.settings_dict, 'sp.entityId')

    @property
    def issuer_id(self):
        return self.entity_id

    @property
    def service_uuid(self):
        try:
            return self.settings_dict['sp']['attributeConsumingService']['requestedAttributes'][0]['attributeValue'][0]
        except KeyError as key_error:
            raise KeyError('key does not exist. please check your settings.json') from key_error

    @property
    def service_name(self):
        return from_settings(self.settings_dict, 'sp.attributeConsumingService.serviceName', 'CoronaCheck')

    @property
    def service_desc(self):
        return from_settings(self.settings_dict, 'sp.attributeConsumingService.serviceDescription', 'CoronaCheck Inlogservice')

    @property
    def acs_url(self):
        return from_settings(self.settings_dict, 'sp.assertionConsumerService.url')

    @property
    def acs_binding(self):
        return from_settings(self.settings_dict, 'sp.assertionConsumerService.binding')

    def get_cert_data(self, key: Optional[str]):
        if key is None:
            cert_path = self.signing_cert_path
        else:
            cert_path = self.cluster_settings[key]['cert_path']

        with open(cert_path, 'r', encoding='utf-8') as cert_file:
            cert_data = cert_file.read()

        return cert_data

    def get_spsso(self, key: Optional[str]):
        cert = self.get_cert_data(key)
        keyname = compute_keyname(cert)
        self.dv_keynames.append(keyname)
        return {
            'cert': strip_cert(cert),
            'keyname': keyname,
            'acs_binding': self.acs_binding,
            'acs_url': self.acs_url,
        }

    def create_entity_descriptor(self, key: Optional[str]):
        return {
            'id': "_" + secrets.token_hex(41), # total length 42.
            'entity_id': self.entity_id if key is None else self.cluster_settings[key]['entity_id'],
            'spsso': self.get_spsso(key)
        }

    def create_cluster_entity_descriptor(self):
        return {
            'clustered_' + key: self.create_entity_descriptor(key)
            for key, _ in self.cluster_settings.items()
        }

    def render_clustered_template(self):
        template = self.jinja_env.get_template(self.CLUSTER_TEMPLATE_NAME)
        clustered_context = {
            'id': self._id_hash,
            'dv_descriptors': self.create_cluster_entity_descriptor(),
            'lc_descriptor': self.create_entity_descriptor(None)
        }

        return template.render(clustered_context)

    def render_unclustered_template(self):
        template = self.jinja_env.get_template(self.TEMPLATE_NAME)
        unclustered_context = {
            'id': self._id_hash,
            'entity_id': self.entity_id,
            'spsso': self.get_spsso(None),
            'service_name': self.service_name,
            'service_desc': self.service_desc,
            'service_uuid': self.service_uuid
        }

        return template.render(unclustered_context)

    def render_template(self) -> str:
        clustered = self.cluster_settings is not None
        if clustered:
            return self.render_clustered_template()

        return self.render_unclustered_template()

    def _valid_signature(self) -> bool:
        with open(self.signing_cert_path, 'r', encoding='utf-8') as cert_file:
            signing_cert = cert_file.read()

        _, is_valid = has_valid_signatures(self.root, cert_data=signing_cert)
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

        if self.cluster_settings is None:
            if self.root.tag != '{%s}EntityDescriptor' % NAMESPACES['md']:
                errors.append('Root is not an EntityDescriptor')

            if len(self.root.findall('.//md:SPSSODescriptor', NAMESPACES)) != 1:
                errors.append('Only one SPSSO Descriptor allowed')
        else:
            if self.root.tag != '{%s}EntitiesDescriptor' % NAMESPACES['md']:
                errors.append('Root is not an EntityDescriptor')

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
        cert_data = enforce_cert_newlines(cert_data)
        return f"""-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----"""

    def get_sso(self, binding='POST') -> Dict[str, str]:
        sso = self.template.find(
            f".//md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-{binding}']",
            {'md': "urn:oasis:names:tc:SAML:2.0:metadata"}
        )
        return get_loc_bind(sso)

    def get_xml(self) -> bytes:
        return etree.tostring(self.template)
