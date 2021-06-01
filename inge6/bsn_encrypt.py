import base64
import json

import nacl.utils
from nacl.secret import SecretBox
from nacl.public import PrivateKey, Box, PublicKey
from nacl.encoding import Base64Encoder

from .config import settings

class BSNEncrypt:
    I6_PRIV_KEY = settings.bsn.i6_priv_key
    I4_PUB_KEY = settings.bsn.i4_pub_key
    SYMM_KEY = settings.bsn.symm_key

    def __init__(self):
        i6_priv_key = PrivateKey(self.I6_PRIV_KEY, encoder=Base64Encoder)
        i4_pub_key = PublicKey(self.I4_PUB_KEY, encoder=Base64Encoder)

        self.box = Box(i6_priv_key, i4_pub_key)
        self.secret_box = SecretBox(bytes.fromhex(self.SYMM_KEY))

    def _symm_encrypt_bsn(self, bsn):
        nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        encrypted_msg = self.secret_box.encrypt(bsn.encode(), nonce=nonce)
        payload = {
            'bsn': Base64Encoder.encode(encrypted_msg.ciphertext).decode(),
            'nonce': Base64Encoder.encode(encrypted_msg.nonce).decode()
        }
        return base64.b64encode(json.dumps(payload).encode())

    def _symm_decrypt_bsn(self, bsn_dict):
        nonce = Base64Encoder.decode(bsn_dict['nonce'].encode())
        ciphertext = Base64Encoder.decode(bsn_dict['bsn'].encode())
        return self.secret_box.decrypt(ciphertext, nonce=nonce)

    def _pub_encrypt_bsn(self, bsn, access_token_value):
        nonce = (access_token_value + 'CC').encode()
        encrypted_bsn = self.box.encrypt(bsn, nonce=nonce, encoder=Base64Encoder)
        return encrypted_bsn
