import base64

from Crypto.Cipher import AES
from lxml import etree

from onelogin.saml2.utils import OneLogin_Saml2_Utils

from ...config import settings

class ArtifactResponseParser():
    PRIV_KEY_PATH = settings.saml.key_path

    def __init__(self, xml_response):
        self.root = etree.fromstring(xml_response).getroottree().getroot()
        with open(self.PRIV_KEY_PATH, 'r') as priv_key_file:
            self.key = priv_key_file.read()

    def _decrypt_enc_key(self) -> bytes:
        encrypted_key_el = self.root.find('.//xenc:EncryptedKey', {'xenc': 'http://www.w3.org/2001/04/xmlenc#'})
        aes_key = OneLogin_Saml2_Utils.decrypt_element(encrypted_key_el, self.key, debug=True)
        return aes_key

    def _remove_padding(self, enc_data):
        return enc_data[:-enc_data[-1]]

    def _decrypt_enc_data(self, aes_key: bytes) -> bytes:
        encrypted_ciphervalue = self.root.find('.//xenc:EncryptedData//xenc:CipherValue', {'xenc': 'http://www.w3.org/2001/04/xmlenc#'}).text
        b64decoded_data = base64.b64decode(encrypted_ciphervalue.encode())
        iv = b64decoded_data[:16]
        enc_data = b64decoded_data[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        plaintext = cipher.decrypt(enc_data)
        return self._remove_padding(plaintext)

    def get_bsn(self):
        aes_key = self._decrypt_enc_key()
        bsn_element_raw = self._decrypt_enc_data(aes_key)
        bsn_element = etree.fromstring(bsn_element_raw.decode())
        return bsn_element.text
