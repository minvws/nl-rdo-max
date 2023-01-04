"""
Handles parsing of Artifact responses, validating the signature among other validity checks.
todo: check class for tests and comments like required settings
Required settings:
    - settings.saml.response_expires_in, number of seconds a generated artifact response is considered valid
"""
import base64
import logging
import re
from datetime import datetime, timedelta
from functools import cached_property
from logging import Logger
# pylint: disable=c-extension-no-member
from typing import Text, List

import dateutil.parser
from Cryptodome.Cipher import AES
from lxml import etree
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from .constants import NAMESPACES
from .exceptions import UserNotAuthenticated, ValidationError
from .saml_identity_provider import SamlIdentityProvider
from ...misc.saml_utils import has_valid_signatures, remove_padding

CAMEL_TO_SNAKE_RE = re.compile(r"(?<!^)(?=[A-Z])")


def verify_signatures(tree, cert_data):
    root, valid = has_valid_signatures(tree, cert_data=cert_data)
    if not valid:
        raise ValidationError("Invalid signatures")

    return root


# pylint: disable=too-many-instance-attributes, too-many-public-methods
class ArtifactResponse:
    def __init__(
            self,
            artifact_tree,
            provider: SamlIdentityProvider,
            is_verified: bool = True,
            strict: bool = True,
            use_cluster_key: bool = False,
    ) -> None:
        # fixme: conf
        self.response_expires_in = 60

        self.log: Logger = logging.getLogger(__package__)

        self.id_provider = provider
        self.is_verified = is_verified
        self.strict = strict
        self.use_cluster_key = use_cluster_key
        self._root = artifact_tree
        self._response = None
        self._response_status = None
        self._saml_status_code = None
        self._status = None
        self._response_audience_restriction = None
        self._response_assertion = None
        self._assertion_subject_confdata = None
        self._assertion_subject_audrestriction = None
        self._assertion_attribute_enc_key = None
        self._assertion_attribute_enc_data = None
        self._issuer = None
        self._response_issuer = None
        self._assertion_issuer = None

        self.validate()

    @classmethod
    def from_string(
            cls,
            xml_response: str,
            provider: SamlIdentityProvider,
            insecure=False,
            strict: bool = True,
            use_cluster_key: bool = False
    ):
        # Remove XML declaration if exists, appears etree doesn't handle it too well.
        xml_response = xml_response.split('<?xml version="1.0" encoding="UTF-8"?>\n')[
            -1
        ]
        artifact_response_tree = etree.fromstring(xml_response).getroottree().getroot()
        return cls.parse(
            artifact_response_tree, provider, insecure, strict=strict, use_cluster_key=use_cluster_key
        )

    @classmethod
    def parse(
            cls,
            artifact_response_tree,
            provider: SamlIdentityProvider,
            insecure=False,
            strict: bool = True,
            use_cluster_key: bool = False
    ):
        unverified_tree = artifact_response_tree.find(
            ".//samlp:ArtifactResponse", NAMESPACES
        )
        if insecure:
            return cls(unverified_tree, provider, False, strict=strict, use_cluster_key=use_cluster_key)

        verified_tree = verify_signatures(
            artifact_response_tree, provider.idp_metadata.get_cert_pem_data()
        )
        return cls(verified_tree, provider, True, strict=strict, use_cluster_key=use_cluster_key)

    @property
    def root(self):
        return self._root

    @property
    def allowed_recipients(self):
        entity_id = self.id_provider.sp_metadata.entity_id
        if not self.id_provider.sp_metadata.clustered:
            return [entity_id]

        return [conn.entity_id for conn in self.id_provider.sp_metadata.connections] + [
            entity_id
        ]

    @cached_property
    def response(self):
        return self.root.find(".//samlp:Response", NAMESPACES)

    @cached_property
    def response_status(self):
        return self.response.find("./samlp:Status", NAMESPACES)

    @cached_property
    def saml_status_code(self) -> str:
        top_level_status_code = self.response_status.find(
            "./samlp:StatusCode", NAMESPACES
        )

        if top_level_status_code.attrib["Value"].split(":")[-1].lower() != "success":
            second_level = top_level_status_code.find("./samlp:StatusCode", NAMESPACES)
            return second_level.attrib["Value"]

        return top_level_status_code.attrib["Value"]

    @cached_property
    def status(self) -> str:
        status = self.saml_status_code.split(":")[-1]
        return "saml_" + CAMEL_TO_SNAKE_RE.sub("_", status).lower()

    @cached_property
    def response_audience_restriction(self):
        return self.response.find(".//saml:AudienceRestriction", NAMESPACES)

    @cached_property
    def response_assertion(self):
        return self.response.find("./saml:Assertion", NAMESPACES)

    @cached_property
    def assertion_attribute_statement(self):
        return self.response_assertion.find("./saml:AttributeStatement", NAMESPACES)

    @cached_property
    def attributes(self):
        attribute_elems = self.assertion_attribute_statement.findall(
            "./saml:Attribute", NAMESPACES
        )
        attributes = {}
        for elem in attribute_elems:
            value = elem.find("./saml:AttributeValue", NAMESPACES)
            if len(value) == 1:
                encrypted_id = value.find("./saml2:EncryptedID", NAMESPACES)
                if encrypted_id is not None:
                    recipient = encrypted_id.find(
                        "./xenc:EncryptedKey", NAMESPACES
                    ).attrib.get("Recipient")
                    if (
                            self.strict
                            and recipient != self.id_provider.sp_metadata.entity_id
                    ):
                        self.log.debug(
                            "Recipients did not match. Was %s, expected %s",
                            recipient,
                            self.id_provider.sp_metadata.entity_id,
                        )
                    else:
                        value = self.decrypt_id(encrypted_id)

            attributes[elem.attrib.get("Name")] = value

        return attributes

    def decrypt_id(self, encrypted_id):
        enc_key_elem = encrypted_id.find("./xenc:EncryptedKey", NAMESPACES)
        enc_data_elem = encrypted_id.find("./xenc:EncryptedData", NAMESPACES)

        keyname = enc_key_elem.find(".//ds:KeyName", NAMESPACES).text
        possible_keynames = self.id_provider.sp_metadata.dv_keynames
        if keyname not in possible_keynames:
            raise ValueError(f"KeyName {keyname} is unknown, cannot decrypt")

        aes_key = self._decrypt_enc_key(enc_key_elem)
        raw_id_element = self._decrypt_enc_data(enc_data_elem, aes_key)
        decrypted_id_element = etree.fromstring(raw_id_element.decode())
        return decrypted_id_element

    @cached_property
    def issuer(self):
        return self.root.find("./saml:Issuer", NAMESPACES)

    @cached_property
    def response_issuer(self):
        return self.response.find("./saml:Issuer", NAMESPACES)

    @cached_property
    def assertion_issuer(self):
        return self.response_assertion.find("./saml:Issuer", NAMESPACES)

    @cached_property
    def assertion_subject(self):
        return self.response_assertion.find("./saml:Subject", NAMESPACES)

    @cached_property
    def assertion_subject_confdata(self):
        return self.assertion_subject.find(
            ".//saml:SubjectConfirmationData", NAMESPACES
        )

    @cached_property
    def assertion_subject_audrestriction(self):
        return self.response_assertion.find(
            "./saml:Conditions//saml:Audience", NAMESPACES
        )

    def raise_for_status(self) -> str:
        if self.status != "saml_success":
            raise UserNotAuthenticated(
                "User authentication flow failed", oauth_error=self.status
            )

        return self.status

    def validate_in_response_to(self) -> List[ValidationError]:
        # fixme: from conf
        expected_entity_id = self.id_provider.expected_entity_id
        response_conditions_aud = self.response_audience_restriction.find(
            ".//saml:Audience", NAMESPACES
        )

        errors = []
        if expected_entity_id is None:
            errors.append(ValidationError("Could not read entity id from settings"))

        if response_conditions_aud is None:
            errors.append(
                ValidationError(
                    "Could not find response conditions audience in artifact response"
                )
            )

        if response_conditions_aud.text != expected_entity_id:
            errors.append(
                ValidationError(
                    f"Invalid audience in response Conditions. Expected {expected_entity_id}, but was {response_conditions_aud.text}"
                )
            )

        return errors

    def validate_issuer_texts(self) -> List[ValidationError]:
        expected_entity_id = self.id_provider.idp_metadata.entity_id
        errors = []
        if self.issuer.text != expected_entity_id:
            errors.append(
                ValidationError(
                    f"Invalid issuer in artifact response. Expected {expected_entity_id}, but was {self.issuer.text}"
                )
            )

        if self.response_issuer.text != expected_entity_id:
            errors.append(
                ValidationError(
                    f"Invalid issuer in artifact response_issuer. Expected {expected_entity_id}, but was {self.response_issuer.text}"
                )
            )

        if self.status == "saml_success":
            if self.assertion_issuer.text != expected_entity_id:
                errors.append(
                    ValidationError(
                        f"Invalid issuer in artifact assertion_issuer. Expected {expected_entity_id}, but was {self.assertion_issuer.text}"
                    )
                )

        return errors

    def validate_recipient_uri(self) -> List[ValidationError]:
        errors = []

        expected_response_dest = self.id_provider.expected_response_destination

        if self.id_provider.saml_is_new_version:
            if expected_response_dest != self.response.attrib["Destination"]:
                errors.append(
                    ValidationError(
                        f"Response destination is not what was expected. Expected: {expected_response_dest}, was {self.response.attrib['Destination']}"
                    )
                )

        if self.status == "saml_success":
            if (
                    expected_response_dest
                    != self.assertion_subject_confdata.attrib["Recipient"]
            ):
                errors.append(
                    ValidationError(
                        f"Recipient in assertion subject confirmation data was not as expected. Expected {expected_response_dest}, was {self.assertion_subject_confdata.attrib['Recipient']}"
                    )
                )  # pylint: disable=line-too-long

        return errors

    def validate_time_restrictions(self) -> List[ValidationError]:
        errors = []
        current_instant = datetime.utcnow()

        issue_instant_els = self.root.findall(".//*[@IssueInstant]")
        for elem in issue_instant_els:
            issue_instant = dateutil.parser.parse(
                elem.attrib["IssueInstant"], ignoretz=True
            )
            expiration_time = issue_instant + timedelta(
                seconds=self.response_expires_in
            )
            if current_instant > expiration_time:
                errors.append(
                    ValidationError(
                        f"Issued ArtifactResponse:{elem.tag} has expired. Current time: {current_instant}, issue instant expiration time: {expiration_time}"
                    )
                )

        issue_instant_els = self.root.findall(".//*[@NotBefore]")
        for elem in issue_instant_els:
            not_before_time = dateutil.parser.parse(
                elem.attrib["NotBefore"], ignoretz=True
            )
            if current_instant < not_before_time:
                errors.append(
                    ValidationError(
                        f"Message should not be processed before {not_before_time}, but is processed at time: {current_instant}"
                    )
                )

        issue_instant_els = self.root.findall(".//*[@NotOnOrAfter]")
        for elem in issue_instant_els:
            not_on_or_after = dateutil.parser.parse(
                elem.attrib["NotOnOrAfter"], ignoretz=True
            )
            if current_instant >= not_on_or_after:
                errors.append(
                    ValidationError(
                        f"Message should not be processed on or after {not_on_or_after}, but is processed at time: {current_instant}"
                    )
                )

        return errors

    def validate_attribute_statement(self, root):
        errors = []

        service_id_attr_val = list(
            root.find("./*[@Name='urn:nl-eid-gdi:1.0:ServiceUUID']")
        )[0].text

        expected_service_uuid = self.id_provider.expected_service_uuid
        if service_id_attr_val != expected_service_uuid:
            errors.append(
                ValidationError(
                    f"service uuid does not comply with specified uuid. Expected {expected_service_uuid}, was {service_id_attr_val}"
                )
            )

        return errors

    def validate_attribute_statements(self):
        errors = []

        response_assertion_attrstatement = self.response_assertion.find(
            ".//saml:AttributeStatement", NAMESPACES
        )
        errors += self.validate_attribute_statement(response_assertion_attrstatement)

        return errors

    def validate_authn_statement(self):
        errors = []

        current_instant = datetime.utcnow()
        issue_instant_text = self.response_assertion.find(
            ".//saml:AuthnStatement", NAMESPACES
        ).attrib["AuthnInstant"]
        issue_instant = dateutil.parser.parse(issue_instant_text, ignoretz=True)
        expiration_time = issue_instant + timedelta(seconds=self.response_expires_in)
        if current_instant > expiration_time:
            errors.append(
                ValidationError(
                    f"Authn instant's datetime is expired. Current time {current_instant}, expiration time {expiration_time}"
                )
            )

        # Authenticating authority is the AD: AuthenticatieDienst, we only know RD: RouteringsDienst.
        # authenticating_authority = self.response_assertion.find('.//saml:AuthenticatingAuthority', NAMESPACES).text
        # expected_authority = self.id_provider.idp_metadata.entity_id
        # if authenticating_authority != expected_authority:
        #     errors.append(ValidationError('Authority is not as expected. Expected {}, was {}'.format(expected_authority, authenticating_authority)))

        return errors

    def validate(self) -> None:
        errors = []

        errors += self.validate_time_restrictions()

        errors += self.validate_issuer_texts()
        errors += self.validate_recipient_uri()

        if self.status == "saml_success":
            errors += self.validate_in_response_to()
            errors += self.validate_authn_statement()

            if self.id_provider.saml_is_new_version:
                errors += self.validate_attribute_statements()

        if len(errors) != 0:
            self.log.error(errors)
            if self.strict:
                raise ValidationError("Audience verification errors.")

    def _decrypt_enc_key(self, enc_key_elem) -> bytes:
        priv_key = self.id_provider.cluster_priv_key if self.use_cluster_key else self.id_provider.priv_key
        aes_key = OneLogin_Saml2_Utils.decrypt_element(
            enc_key_elem, priv_key, debug=True
        )
        return aes_key

    # pylint: disable=no-self-use
    def _decrypt_enc_data(self, enc_data_elem, aes_key: bytes) -> bytes:
        encrypted_ciphervalue = enc_data_elem.find(
            ".//xenc:CipherValue", {"xenc": "http://www.w3.org/2001/04/xmlenc#"}
        ).text
        b64decoded_data = base64.b64decode(encrypted_ciphervalue.encode())
        init_vector = b64decoded_data[:16]
        enc_data = b64decoded_data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=init_vector)
        plaintext = cipher.decrypt(enc_data)
        return remove_padding(plaintext)

    def _plaintext_bsn(self):
        return self.assertion_subject.find("./saml:NameID", NAMESPACES)

    def get_bsn(self, authorization_by_proxy: bool) -> Text:
        if self.id_provider.saml_is_new_version:
            if "urn:nl-eid-gdi:1.0:LegalSubjectID" in self.attributes:
                self.log.info(
                    "Using LegalSubjectID from ArtifactResponse. User retrieving BSN as 'gemachtigde'"
                )
                bsn_element = self.attributes["urn:nl-eid-gdi:1.0:LegalSubjectID"]
            else:
                if authorization_by_proxy:
                    raise ValueError(
                        "Expected LegalSubjectID in the attributes, but was not found."
                    )
                bsn_element = self.attributes["urn:nl-eid-gdi:1.0:ActingSubjectID"]

        else:
            bsn_element = self._plaintext_bsn()
        return bsn_element.text

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
