# pylint: disable=c-extension-no-member
from typing import Text

import base64
import re
import json
import logging

from typing import List, Any

from Crypto.Cipher import AES
from lxml import etree

from onelogin.saml2.utils import OneLogin_Saml2_Utils

from ..config import settings
from .utils import from_settings, has_valid_signatures, remove_padding
from .constants import NAMESPACES
from .exceptions import UserNotAuthenticated, ValidationError
from .provider import SAMLProvider

SUCCESS = "success"

PRIV_KEY_PATH = settings.saml.key_path
CAMEL_TO_SNAKE_RE = re.compile(r'(?<!^)(?=[A-Z])')


def verify_signatures(tree, cert_data):
    root, valid = has_valid_signatures(tree, cert_data=cert_data)
    if not valid:
        raise ValidationError("Invalid signatures")

    return root


class ArtifactResponse:

    def __init__(self, artifact_tree, is_verified: bool = True) -> None:
        self.is_verifeid = is_verified

        self._root = artifact_tree
        self._reponse = None
        self._response_status = None
        self._saml_status_code = None
        self._status = None

    @staticmethod
    def from_string(cls, xml_response: str, provider: SAMLProvider):
        artifact_response_tree = etree.fromstring(xml_response).getroottree().getroot()
        return cls.parse(artifact_response_tree, provider)
    
    @staticmethod
    def parse(cls, artifact_response_tree, provider: SAMLProvider):
        verified_tree = verify_signatures(artifact_response_tree, provider.idp_metadata.get_cert_pem_data())
        return cls(verified_tree, True)

    @property
    def root(self):
        return self._root

    @property
    def response(self):
        if self._response is not None:
            return self._response

        self._response = self.root.find('.//samlp:Response', NAMESPACES)
        return self._response

    @property
    def response_status(self):
        if self._response_status is not None:
            return self._response_status

        self._response_status = self.response.find('./samlp:Status', NAMESPACES)
        return self._response_status

    @property
    def saml_status_code(self) -> str:
        if self._saml_status_code is not None:
            return self._saml_status_code

        top_level_status_code = self.response_status.find('./samlp:StatusCode', NAMESPACES)
        if top_level_status_code.attrib['Value'].split(':')[-1].lower() != SUCCESS:
            second_level = top_level_status_code.find('./samlp:StatusCode', NAMESPACES)
            self._saml_status_code = second_level.attrib['Value']
            return self._saml_status_code

        self._saml_status_code = top_level_status_code.attrib['Value']
        return self._saml_status_code
     
    @property
    def status(self) -> str:
        if self._status is None:
            return self._status
        status = self.saml_status.split(':')[-1]
        self._status = 'saml_' + CAMEL_TO_SNAKE_RE.sub('_', status).lower()   
        return self._status

    def raise_for_status(self) -> str:
        if self.status != 'saml_' + SUCCESS:
            raise UserNotAuthenticated("User authentication flow failed", oauth_error=status)

        return self.status

    def verify_in_response_to(self, artifact_resp_tree) -> List[ValidationError]:
        expected_entity_id = from_settings(settings_dict, 'sp.entityId')
        response_conditions_aud = artifact_resp_tree.find('.//md:ArtifactResponse/samlp:Response//saml:AudienceRestriction/saml:Audience', NAMESPACES)
        
        errors = []
        if expected_entity_id is None:
            errors.append(ValidationError('Could not read entity id from settings'))

        if response_conditions_aud is None:
            errors.append(ValidationError('Could not find response conditions audience in artifact response'))
        
        if response_conditions_aud.text == expected_entity_id:
            errors.append(ValidationError('Invalid audience in response Conditions'))

        response_advice_encrypted_key_aud = artifact_resp_tree.find('.//md:ArtifactResponse/samlp:Response//saml2:Assertion/xenc:EncryptedKey', NAMESPACES)
        if response_advice_encrypted_key_aud.attrib['Recipient'] == expected_entity_id:
            errors.append(ValidationError('Invalid audience in response Conditions'))
        
        return errors


    def verify(self):
        audience_errors = self.verify_in_response_to()
        if len(audience_errors) != 0:
            logging.error(audience_errors)
            raise ValidationError('Audience verification errors.')
        return self.verify_signatures()

    def _decrypt_enc_key(self) -> bytes:
        encrypted_key_el = self.root.find('.//xenc:EncryptedKey', {'xenc': 'http://www.w3.org/2001/04/xmlenc#'})
        aes_key = OneLogin_Saml2_Utils.decrypt_element(encrypted_key_el, self.key, debug=True)
        return aes_key

    def _decrypt_enc_data(self, aes_key: bytes) -> bytes:
        encrypted_ciphervalue = self.root.find('.//xenc:EncryptedData//xenc:CipherValue', {'xenc': 'http://www.w3.org/2001/04/xmlenc#'}).text
        b64decoded_data = base64.b64decode(encrypted_ciphervalue.encode())
        init_vector = b64decoded_data[:16]
        enc_data = b64decoded_data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=init_vector)
        plaintext = cipher.decrypt(enc_data)
        return remove_padding(plaintext)

    def get_bsn(self) -> Text:
        aes_key = self._decrypt_enc_key()
        bsn_element_raw = self._decrypt_enc_data(aes_key)
        bsn_element = etree.fromstring(bsn_element_raw.decode())
        return bsn_element.text
