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

from ..config import settings
from .utils import from_settings, has_valid_signatures, remove_padding
from .constants import NAMESPACES
from .exceptions import UserNotAuthenticated, ValidationError
from .provider import Provider as SAMLProvider

RESPONSE_EXPIRES_IN = int(settings.saml.response_expires_in)

PRIV_KEY_PATH = settings.saml.key_path
CAMEL_TO_SNAKE_RE = re.compile(r'(?<!^)(?=[A-Z])')

log: Logger = logging.getLogger(__package__)

def verify_signatures(tree, cert_data):
    root, valid = has_valid_signatures(tree, cert_data=cert_data)
    if not valid:
        raise ValidationError("Invalid signatures")

    return root

# pylint: disable=too-many-instance-attributes, too-many-public-methods
class ArtifactResponse:

    def __init__(self,
                 artifact_tree,
                 provider: SAMLProvider,
                 saml_specification_version: float = 4.5,
                 is_verified: bool = True,
                 is_test_instance: bool = False
        ) -> None:

        self.saml_specification_version = saml_specification_version
        self.provider = provider
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
    def from_string(cls, xml_response: str, provider: SAMLProvider, saml_specification_version: float = 4.5,
                    insecure=False, is_test_instance: bool=False):
        artifact_response_tree = etree.fromstring(xml_response).getroottree().getroot()
        return cls.parse(artifact_response_tree, provider, saml_specification_version, insecure, is_test_instance)

    @classmethod
    def parse(cls, artifact_response_tree, provider: SAMLProvider, saml_specification_version: float = 4.5,
              insecure=False, is_test_instance: bool=False):
        unverified_tree = artifact_response_tree.find('.//samlp:ArtifactResponse', NAMESPACES)
        if insecure:
            return cls(unverified_tree, provider, saml_specification_version, False, is_test_instance)

        verified_tree = verify_signatures(artifact_response_tree, provider.idp_metadata.get_cert_pem_data())
        return cls(verified_tree, provider, saml_specification_version, True, is_test_instance)

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
        expected_entity_id = from_settings(self.provider.settings_dict, 'sp.entityId')
        response_conditions_aud = self.response_audience_restriction.find('.//saml:Audience', NAMESPACES)

        errors = []
        if expected_entity_id is None:
            errors.append(ValidationError('Could not read entity id from settings'))

        if response_conditions_aud is None:
            errors.append(ValidationError('Could not find response conditions audience in artifact response'))

        if response_conditions_aud.text != expected_entity_id:
            errors.append(ValidationError('Invalid audience in response Conditions. Expected {}, but was {}'.format(expected_entity_id, response_conditions_aud.text)))

        if self.saml_specification_version >= 4.4:
            response_advice_encrypted_key_aud = self.assertion_attribute_enc_key
            if response_advice_encrypted_key_aud.attrib['Recipient'] != expected_entity_id:
                errors.append(ValidationError('Invalid audience in encrypted key. Expected {}, but was {}'.format(expected_entity_id, response_advice_encrypted_key_aud.attrib['Recipient'])))

            if self.assertion_subject_audrestriction.text != expected_entity_id:
                errors.append(ValidationError('Invalid issuer in artifact assertion_subject_audrestriction. Expected {}, but was {}'.format(expected_entity_id, self.assertion_subject_audrestriction.text)))

        return errors

    def validate_issuer_texts(self) -> List[ValidationError]:
        expected_entity_id = self.provider.idp_metadata.entity_id
        errors = []
        if self.issuer.text != expected_entity_id:
            errors.append(ValidationError('Invalid issuer in artifact response. Expected {}, but was {}'.format(expected_entity_id, self.issuer.text)))

        if self.response_issuer.text != expected_entity_id:
            errors.append(ValidationError('Invalid issuer in artifact response_issuer. Expected {}, but was {}'.format(expected_entity_id, self.response_issuer.text)))

        if self.status == 'saml_success':
            if self.assertion_issuer.text != expected_entity_id:
                errors.append(ValidationError('Invalid issuer in artifact assertion_issuer. Expected {}, but was {}'.format(expected_entity_id, self.assertion_issuer.text)))

            # RD V.S. AD. we cannot perform this check
            # if self.advice_assertion_issuer.text != self.provider.idp_metadata.entity_id:
            #     errors.append(ValidationError('Invalid issuer in artifact advice_assertion_issuer. Expected {}, but was {}'.format(expected_entity_id, self.advice_assertion_issuer.text)))

        return errors

    def validate_recipient_uri(self) -> List[ValidationError]:
        errors = []

        expected_response_dest = from_settings(self.provider.settings_dict, 'sp.assertionConsumerService.url')
        # TODO: remove, or related to saml specification 3.5 vs 4.5?
        if self.saml_specification_version >= 4.4:
            if expected_response_dest != self.response.attrib['Destination']:
                errors.append(ValidationError('Response destination is not what was expected. Expected: {}, was {}'.format(expected_response_dest, self.response.attrib['Destination'])))

        if self.status == 'saml_success':
            if expected_response_dest != self.assertion_subject_confdata.attrib['Recipient']:
                errors.append(ValidationError('Recipient in assertion subject confirmation data was not as expected. Expected {}, was {}'
                                            .format(expected_response_dest, self.assertion_subject_confdata.attrib['Recipient'])))

        return errors

    def validate_time_restrictions(self) -> List[ValidationError]:
        errors = []
        current_instant = datetime.utcnow()

        issue_instant_els = self.root.findall(".//*[@IssueInstant]")
        for elem in issue_instant_els:
            issue_instant = dateutil.parser.parse(elem.attrib['IssueInstant'], ignoretz=True)
            expiration_time = issue_instant + timedelta(seconds= RESPONSE_EXPIRES_IN)
            if current_instant > expiration_time:
                errors.append(ValidationError("Issued ArtifactResponse:{} has expired. Current time: {}, issue instant expiration time: {}".format(elem.tag, current_instant, expiration_time)))

        issue_instant_els = self.root.findall(".//*[@NotBefore]")
        for elem in issue_instant_els:
            not_before_time = dateutil.parser.parse(elem.attrib['NotBefore'], ignoretz=True)
            if current_instant < not_before_time:
                errors.append(ValidationError("Message should not be processed before {}, but is processed at time: {}".format(not_before_time, current_instant)))

        issue_instant_els = self.root.findall(".//*[@NotOnOrAfter]")
        for elem in issue_instant_els:
            not_on_or_after = dateutil.parser.parse(elem.attrib['NotOnOrAfter'], ignoretz=True)
            if current_instant >= not_on_or_after:
                errors.append(ValidationError("Message should not be processed on or after {}, but is processed at time: {}".format(not_on_or_after, current_instant)))

        return errors

    def validate_attribute_statement(self, root):
        errors = []

        service_id_attr_val = list(root.find("./*[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']"))[0].text
        expected_service_uuid = from_settings(self.provider.sp_metadata.settings_dict, 'sp.attributeConsumingService.requestedAttributes.0.attributeValue.0')
        if service_id_attr_val != expected_service_uuid:
            errors.append(ValidationError("service uuid does not comply with specified uuid. Expected {}, was {}".format(expected_service_uuid, service_id_attr_val)))

        if not self.is_test_instance and self.is_verifeid:
            # Only perform this validation if it is verified, and not a test instance.
            keyname = root.find('.//ds:KeyName', NAMESPACES).text
            expected_keyname = self.provider.sp_metadata.keyname
            if keyname != expected_keyname:
                errors.append(ValidationError("KeyName does not comply with specified keyname. Expected {}, was {}".format(expected_keyname, keyname)))

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
            expiration_time = issue_instant + timedelta(seconds= RESPONSE_EXPIRES_IN)
            if current_instant > expiration_time:
                errors.append(ValidationError('Authn instant\'s datetime is expired. Current time {}, expiration time {}'.format(current_instant, expiration_time)))

        # Authenticating authority is the AD: AuthenticatieDienst, we only know RD: RouteringsDienst.
        # authenticating_authority = self.response_assertion.find('.//saml:AuthenticatingAuthority', NAMESPACES).text
        # expected_authority = self.provider.idp_metadata.entity_id
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

            if self.saml_specification_version >= 4.4:
                errors += self.validate_attribute_statements()

        if len(errors) != 0:
            log.error(errors)
            raise ValidationError('Audience verification errors.')

    def _decrypt_enc_key(self) -> bytes:
        aes_key = OneLogin_Saml2_Utils.decrypt_element(self.assertion_attribute_enc_key, self.provider.priv_key, debug=True)
        return aes_key

    def _decrypt_enc_data(self, aes_key: bytes) -> bytes:
        encrypted_ciphervalue = self.assertion_attribute_enc_data.find('.//xenc:CipherValue', {'xenc': 'http://www.w3.org/2001/04/xmlenc#'}).text
        b64decoded_data = base64.b64decode(encrypted_ciphervalue.encode())
        init_vector = b64decoded_data[:16]
        enc_data = b64decoded_data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=init_vector)
        plaintext = cipher.decrypt(enc_data)
        return remove_padding(plaintext)

    def _decrypt_bsn(self) -> Text:
        aes_key = self._decrypt_enc_key()
        bsn_element_raw = self._decrypt_enc_data(aes_key)
        bsn_element = etree.fromstring(bsn_element_raw.decode())
        return bsn_element

    def _plaintext_bsn(self) -> Text:
        return self.assertion_subject.find('./saml:NameID', NAMESPACES)

    def get_bsn(self) -> Text:
        if self.saml_specification_version >= 4.4:
            bsn_element = self._decrypt_bsn()
        else:
            bsn_element = self._plaintext_bsn()
        return bsn_element.text
