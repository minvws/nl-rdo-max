# pylint: disable=c-extension-no-member
import base64
import re

from Crypto.Cipher import AES
from lxml import etree

from onelogin.saml2.utils import OneLogin_Saml2_Utils

from ..config import settings
from .utils import has_valid_signatures, remove_padding
from .constants import NAMESPACES
from .exceptions import UserNotAuthenticated
from .idp_metadata import idp_metadata

SUCCESS = "success"

CAMEL_TO_SNAKE_RE = re.compile(r'(?<!^)(?=[A-Z])')

# pylint: disable=too-few-public-methods
class ArtifactResponseParser():
    PRIV_KEY_PATH = settings.saml.key_path

    def __init__(self, xml_response, verify=True):
        self.root = etree.fromstring(xml_response).getroottree().getroot()
        with open(self.PRIV_KEY_PATH, 'r') as priv_key_file:
            self.key = priv_key_file.read()

        if verify:
            self.verify_signatures()

    def get_top_level_status_elem(self):
        top_level_status_elem = self.root.find('.//samlp:ArtifactResponse/samlp:Status/samlp:StatusCode', NAMESPACES)
        return top_level_status_elem

    def get_second_level_status(self):
        top_level = self.root.find('.//samlp:Response//samlp:StatusCode', NAMESPACES)
        if top_level.attrib['Value'].split(':')[-1].lower() != SUCCESS:
            second_level = top_level.find('./samlp:StatusCode', NAMESPACES)
            return second_level.attrib['Value']

        return top_level.attrib['Value']

    def get_status(self):
        status = self.get_second_level_status()
        status = status.split(':')[-1]
        return 'saml_' + CAMEL_TO_SNAKE_RE.sub('_', status).lower()

    def raise_for_status(self):
        status = self.get_status()
        if status != 'saml_' + SUCCESS:
            raise UserNotAuthenticated("User authentication flow failed", oauth_error=status)

        return status

    def _get_artifact_response_elem(self):
        return self.root.find('.//samlp:ArtifactResponse', NAMESPACES)

    def _get_assertion_elem(self):
        return self._get_artifact_response_elem().find('.//saml:Assertion', NAMESPACES)

    def _get_advice_elem(self):
        return self._get_assertion_elem().find('.//saml2:Assertion', NAMESPACES)

    def verify_signatures(self):
        root, valid = has_valid_signatures(self.root, cert_data=idp_metadata.get_cert_pem_data())
        if not valid:
            raise Exception("Invalid signatures")

        self.root = root

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

    def get_bsn(self):
        aes_key = self._decrypt_enc_key()
        bsn_element_raw = self._decrypt_enc_data(aes_key)
        bsn_element = etree.fromstring(bsn_element_raw.decode())
        return bsn_element.text
