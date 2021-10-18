"""
Handles parsing of Artifact responses, validating the signature among other validity checks.

Required settings:
    - settings.saml.response_expires_in, number of seconds a generated artifact response is considered valid
"""
# pylint: disable=c-extension-no-member
from typing import Text, List

import base64
import re
import logging
from logging import Logger

from datetime import datetime, timedelta
from functools import cached_property

import dateutil.parser

from Crypto.Cipher import AES
from lxml import etree

from onelogin.saml2.utils import OneLogin_Saml2_Utils

from ..config import Settings
from .utils import from_settings, has_valid_signatures, remove_padding
from .constants import NAMESPACES
from .exceptions import UserNotAuthenticated, ValidationError
from .id_provider import IdProvider


CAMEL_TO_SNAKE_RE = re.compile(r'(?<!^)(?=[A-Z])')


def verify_signatures(tree, cert_data):
    root, valid = has_valid_signatures(tree, cert_data=cert_data)
    if not valid:
        raise ValidationError("Invalid signatures")

    return root


# pylint: disable=too-many-instance-attributes, too-many-public-methods
class ArtifactResponse:

    def __init__(self,
                 settings: Settings,
                 artifact_tree,
                 provider: IdProvider,
                 is_verified: bool = True,
                 is_test_instance: bool = False
        ) -> None:
        self.settings = settings
        self.response_expires_in = int(self.settings.saml.response_expires_in)

        self.log: Logger = logging.getLogger(__package__)
        self.log.setLevel(getattr(logging, self.settings.loglevel.upper()))

        self.id_provider = provider
        self.is_verifeid = is_verified
        self.is_test_instance = is_test_instance

        self._root = artifact_tree
        self._response = None
        self._response_status = None
        self._saml_status_code = None
        self._status = None
        self._response_audience_restriction = None
        self._response_assertion = None
        self._advice_assertion = None
        self._assertion_subject_confdata = None
        self._assertion_subject_audrestriction = None
        self._assertion_attribute_enc_key = None
        self._assertion_attribute_enc_data = None
        self._issuer = None
        self._response_issuer = None
        self._assertion_issuer = None
        self._advice_assertion_issuer = None

        self.validate()

    @classmethod
    def from_string(cls, settings: Settings, xml_response: str, provider: IdProvider,
                    insecure=False, is_test_instance: bool=False):
        # Remove XML declaration if exists, appears etree doesn't handle it too well.
        xml_response = xml_response.split('<?xml version="1.0" encoding="UTF-8"?>\n')[-1]
        artifact_response_tree = etree.fromstring(xml_response).getroottree().getroot()
        return cls.parse(settings, artifact_response_tree, provider, insecure, is_test_instance)

    @classmethod
    def parse(cls, settings: Settings, artifact_response_tree, provider: IdProvider,
              insecure=False, is_test_instance: bool=False):
        unverified_tree = artifact_response_tree.find('.//samlp:ArtifactResponse', NAMESPACES)
        if insecure:
            return cls(settings, unverified_tree, provider, False, is_test_instance)

        verified_tree = verify_signatures(artifact_response_tree, provider.idp_metadata.get_cert_pem_data())
        return cls(settings, verified_tree, provider, True, is_test_instance)

    @property
    def root(self):
        return self._root

    @cached_property
    def response(self):
        return self.root.find('.//samlp:Response', NAMESPACES)

    @cached_property
    def response_status(self):
        return self.response.find('./samlp:Status', NAMESPACES)

    @cached_property
    def saml_status_code(self) -> str:
        top_level_status_code = self.response_status.find('./samlp:StatusCode', NAMESPACES)

        if top_level_status_code.attrib['Value'].split(':')[-1].lower() != "success":
            second_level = top_level_status_code.find('./samlp:StatusCode', NAMESPACES)
            return second_level.attrib['Value']

        return top_level_status_code.attrib['Value']

    @cached_property
    def status(self) -> str:
        status = self.saml_status_code.split(':')[-1]
        return 'saml_' + CAMEL_TO_SNAKE_RE.sub('_', status).lower()

    @cached_property
    def response_audience_restriction(self):
        return self.response.find('.//saml:AudienceRestriction', NAMESPACES)

    @cached_property
    def response_assertion(self):
        return self.response.find('./saml:Assertion', NAMESPACES)

    @cached_property
    def advice_assertion(self):
        return self.response_assertion.find('.//saml:Assertion', NAMESPACES)

    @cached_property
    def assertion_attribute_enc_key(self):
        return self.response_assertion.find('.//saml2:AttributeStatement//xenc:EncryptedKey', NAMESPACES)

    @cached_property
    def assertion_attribute_enc_data(self):
        return self.response_assertion.find('.//saml2:AttributeStatement//xenc:EncryptedData', NAMESPACES)

    @cached_property
    def issuer(self):
        return self.root.find('./saml:Issuer', NAMESPACES)

    @cached_property
    def response_issuer(self):
        return self.response.find('./saml:Issuer', NAMESPACES)

    @cached_property
    def assertion_issuer(self):
        return self.response_assertion.find('./saml:Issuer', NAMESPACES)

    @cached_property
    def advice_assertion_issuer(self):
        return self.advice_assertion.find('./saml:Issuer', NAMESPACES)

    @cached_property
    def assertion_subject(self):
        return self.response_assertion.find('./saml:Subject', NAMESPACES)

    @cached_property
    def assertion_subject_confdata(self):
        return self.assertion_subject.find('.//saml:SubjectConfirmationData', NAMESPACES)

    @cached_property
    def assertion_subject_audrestriction(self):
        return self.response_assertion.find('./saml:Conditions//saml:Audience', NAMESPACES)

    def raise_for_status(self) -> str:
        if self.status != 'saml_success':
            raise UserNotAuthenticated("User authentication flow failed", oauth_error=self.status)

        return self.status

    def validate_in_response_to(self) -> List[ValidationError]:
        expected_entity_id = from_settings(self.id_provider.settings_dict, 'sp.entityId')
        response_conditions_aud = self.response_audience_restriction.find('.//saml:Audience', NAMESPACES)

        errors = []
        if expected_entity_id is None:
            errors.append(ValidationError('Could not read entity id from settings'))

        if response_conditions_aud is None:
            errors.append(ValidationError('Could not find response conditions audience in artifact response'))

        if response_conditions_aud.text != expected_entity_id:
            errors.append(ValidationError(f'Invalid audience in response Conditions. Expected {expected_entity_id}, but was {response_conditions_aud.text}'))

        if self.id_provider.saml_is_new_version:
            response_advice_encrypted_key_aud = self.assertion_attribute_enc_key

            if self.id_provider.sp_metadata.clustered:
                possible_expected_entity_ids = [self.id_provider.sp_metadata.connections[conn]['entity_id'] for conn in self.id_provider.sp_metadata.connections]
                if response_advice_encrypted_key_aud not in possible_expected_entity_ids:
                    errors.append(ValidationError(f"Invalid audience in encrypted key. Expected on of: {expected_entity_id}, but was {response_advice_encrypted_key_aud.attrib['Recipient']}"))
            else:
                if response_advice_encrypted_key_aud.attrib['Recipient'] != expected_entity_id:
                    errors.append(ValidationError(f"Invalid audience in encrypted key. Expected {expected_entity_id}, but was {response_advice_encrypted_key_aud.attrib['Recipient']}"))

                if self.assertion_subject_audrestriction.text != expected_entity_id:
                    errors.append(ValidationError(f'Invalid issuer in artifact assertion_subject_audrestriction. Expected {expected_entity_id}, but was {self.assertion_subject_audrestriction.text}'))

        return errors

    def validate_issuer_texts(self) -> List[ValidationError]:
        expected_entity_id = self.id_provider.idp_metadata.entity_id
        errors = []
        if self.issuer.text != expected_entity_id:
            errors.append(ValidationError(f'Invalid issuer in artifact response. Expected {expected_entity_id}, but was {self.issuer.text}'))

        if self.response_issuer.text != expected_entity_id:
            errors.append(ValidationError(f'Invalid issuer in artifact response_issuer. Expected {expected_entity_id}, but was {self.response_issuer.text}'))

        if self.status == 'saml_success':
            if self.assertion_issuer.text != expected_entity_id:
                errors.append(ValidationError(f'Invalid issuer in artifact assertion_issuer. Expected {expected_entity_id}, but was {self.assertion_issuer.text}'))

            # RD V.S. AD. we cannot perform this check
            # if self.advice_assertion_issuer.text != self.id_provider.idp_metadata.entity_id:
            #     errors.append(ValidationError('Invalid issuer in artifact advice_assertion_issuer. Expected {}, but was {}'.format(expected_entity_id, self.advice_assertion_issuer.text)))

        return errors

    def validate_recipient_uri(self) -> List[ValidationError]:
        errors = []

        expected_response_dest = from_settings(self.id_provider.settings_dict, 'sp.assertionConsumerService.url')
        # TODO: remove, or related to saml specification 3.5 vs 4.5? # pylint: disable=fixme
        if self.id_provider.saml_is_new_version:
            if expected_response_dest != self.response.attrib['Destination']:
                errors.append(ValidationError(f"Response destination is not what was expected. Expected: {expected_response_dest}, was {self.response.attrib['Destination']}"))

        if self.status == 'saml_success':
            if expected_response_dest != self.assertion_subject_confdata.attrib['Recipient']:
                errors.append(ValidationError(f"Recipient in assertion subject confirmation data was not as expected. Expected {expected_response_dest}, was {self.assertion_subject_confdata.attrib['Recipient']}")) # pylint: disable=line-too-long

        return errors

    def validate_time_restrictions(self) -> List[ValidationError]:
        errors = []
        current_instant = datetime.utcnow()

        issue_instant_els = self.root.findall(".//*[@IssueInstant]")
        for elem in issue_instant_els:
            issue_instant = dateutil.parser.parse(elem.attrib['IssueInstant'], ignoretz=True)
            expiration_time = issue_instant + timedelta(seconds= self.response_expires_in)
            if current_instant > expiration_time:
                errors.append(ValidationError(f"Issued ArtifactResponse:{elem.tag} has expired. Current time: {current_instant}, issue instant expiration time: {expiration_time}"))

        issue_instant_els = self.root.findall(".//*[@NotBefore]")
        for elem in issue_instant_els:
            not_before_time = dateutil.parser.parse(elem.attrib['NotBefore'], ignoretz=True)
            if current_instant < not_before_time:
                errors.append(ValidationError(f"Message should not be processed before {not_before_time}, but is processed at time: {current_instant}"))

        issue_instant_els = self.root.findall(".//*[@NotOnOrAfter]")
        for elem in issue_instant_els:
            not_on_or_after = dateutil.parser.parse(elem.attrib['NotOnOrAfter'], ignoretz=True)
            if current_instant >= not_on_or_after:
                errors.append(ValidationError(f"Message should not be processed on or after {not_on_or_after}, but is processed at time: {current_instant}"))

        return errors

    def validate_attribute_statement(self, root):
        errors = []

        service_id_attr_val = list(root.find("./*[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']"))[0].text
        expected_service_uuid = from_settings(self.id_provider.sp_metadata.settings_dict, 'sp.attributeConsumingService.requestedAttributes.0.attributeValue.0')
        if service_id_attr_val != expected_service_uuid:
            errors.append(ValidationError(f"service uuid does not comply with specified uuid. Expected {expected_service_uuid}, was {service_id_attr_val}"))

        if not self.is_test_instance and self.is_verifeid:
            # Only perform this validation if it is verified, and not a test instance.
            keyname = root.find('.//ds:KeyName', NAMESPACES).text
            possible_keynames = self.id_provider.sp_metadata.dv_keynames
            if keyname not in possible_keynames:
                errors.append(ValidationError(f"KeyName does not comply with one of the specified keynames. Expected list {possible_keynames}, was {keyname}"))

        return errors

    def validate_attribute_statements(self):
        errors = []

        advice_assertion_attrstatement = self.advice_assertion.find('.//saml2:AttributeStatement', NAMESPACES)
        errors += self.validate_attribute_statement(advice_assertion_attrstatement)

        response_assertion_attrstatement = self.response_assertion.find('.//saml:AttributeStatement', NAMESPACES)
        errors += self.validate_attribute_statement(response_assertion_attrstatement)

        return errors

    def validate_authn_statement(self):
        errors = []

        if not self.is_test_instance:
            current_instant = datetime.utcnow()
            issue_instant_text = self.response_assertion.find('.//saml:AuthnStatement', NAMESPACES).attrib['AuthnInstant']
            issue_instant = dateutil.parser.parse(issue_instant_text, ignoretz=True)
            expiration_time = issue_instant + timedelta(seconds=self.response_expires_in)
            if current_instant > expiration_time:
                errors.append(ValidationError(f'Authn instant\'s datetime is expired. Current time {current_instant}, expiration time {expiration_time}'))

        # Authenticating authority is the AD: AuthenticatieDienst, we only know RD: RouteringsDienst.
        # authenticating_authority = self.response_assertion.find('.//saml:AuthenticatingAuthority', NAMESPACES).text
        # expected_authority = self.id_provider.idp_metadata.entity_id
        # if authenticating_authority != expected_authority:
        #     errors.append(ValidationError('Authority is not as expected. Expected {}, was {}'.format(expected_authority, authenticating_authority)))

        return errors

    def validate(self) -> None:
        errors = []

        if not self.is_test_instance:
            errors += self.validate_time_restrictions()

        errors += self.validate_issuer_texts()
        errors += self.validate_recipient_uri()

        if self.status == 'saml_success':
            errors += self.validate_in_response_to()
            errors += self.validate_authn_statement()

            if self.id_provider.saml_is_new_version:
                errors += self.validate_attribute_statements()

        if len(errors) != 0:
            self.log.error(errors)
            raise ValidationError('Audience verification errors.')

    def _decrypt_enc_key(self) -> bytes:
        aes_key = OneLogin_Saml2_Utils.decrypt_element(self.assertion_attribute_enc_key, self.id_provider.priv_key, debug=True)
        return aes_key

    def _decrypt_enc_data(self, aes_key: bytes) -> bytes:
        encrypted_ciphervalue = self.assertion_attribute_enc_data.find('.//xenc:CipherValue', {'xenc': 'http://www.w3.org/2001/04/xmlenc#'}).text
        b64decoded_data = base64.b64decode(encrypted_ciphervalue.encode())
        init_vector = b64decoded_data[:16]
        enc_data = b64decoded_data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=init_vector)
        plaintext = cipher.decrypt(enc_data)
        return remove_padding(plaintext)

    def _decrypt_bsn(self):
        aes_key = self._decrypt_enc_key()
        bsn_element_raw = self._decrypt_enc_data(aes_key)
        bsn_element = etree.fromstring(bsn_element_raw.decode())
        return bsn_element

    def _plaintext_bsn(self):
        return self.assertion_subject.find('./saml:NameID', NAMESPACES)

    def get_bsn(self) -> Text:
        if self.id_provider.saml_is_new_version:
            bsn_element = self._decrypt_bsn()
        else:
            bsn_element = self._plaintext_bsn()
        return bsn_element.text


    def get_enc_key_and_enc_data(self):
        encrypted_keyname = self.assertion_attribute_enc_key.find('.//ds:KeyName', NAMESPACES).text
        encrypted_key = self.assertion_attribute_enc_key.find('.//xenc:CipherValue', NAMESPACES).text
        encrypted_keyalg = self.assertion_attribute_enc_key.find('./xenc:EncryptionMethod', NAMESPACES).attrib['Algorithm']
        encrypted_keydig = self.assertion_attribute_enc_key.find('.//ds:DigestMethod', NAMESPACES).attrib['Algorithm']

        encrypted_data = self.assertion_attribute_enc_data.find('.//xenc:CipherValue', NAMESPACES).text
        encrypted_data_method = self.assertion_attribute_enc_data.find('.//xenc:EncryptionMethod', NAMESPACES).attrib['Algorithm']

        return {
            'key': {
                'name': encrypted_keyname,
                'alg': encrypted_keyalg,
                'dig': encrypted_keydig,
                'value': encrypted_key
            },
            'data': {
                'alg': encrypted_data_method,
                'value': encrypted_data
            }
        }

    def to_string(self) -> bytes:
        return etree.tostring(self.root)

    def to_envelope_string(self) -> str:
        return f"""<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Body>
        {self.to_string().decode()}
    </soapenv:Body>
</soapenv:Envelope>
"""
