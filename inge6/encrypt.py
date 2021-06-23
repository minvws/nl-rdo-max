# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
import base64
import json

from typing import Dict, Any

import nacl.utils
from nacl.secret import SecretBox
from nacl.public import PrivateKey, Box, PublicKey
from nacl.encoding import Base64Encoder

class Encrypt:

    def __init__(self, raw_sign_key: bytes, raw_enc_key: bytes, raw_local_enc_key: str) -> None:
        sign_key = PrivateKey(raw_sign_key, encoder=Base64Encoder)
        enc_key = PublicKey(raw_enc_key, encoder=Base64Encoder)

        self.box = Box(sign_key, enc_key)
        self.secret_box = SecretBox(bytes.fromhex(raw_local_enc_key))

    def symm_encrypt(self, plaintext: str) -> bytes:
        nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        encrypted_msg = self.secret_box.encrypt(plaintext.encode(), nonce=nonce)
        payload = {
            'payload': Base64Encoder.encode(encrypted_msg.ciphertext).decode(),
            'nonce': Base64Encoder.encode(encrypted_msg.nonce).decode()
        }
        return base64.b64encode(json.dumps(payload).encode())

    def symm_decrypt(self, payload: Dict[Any, Any]) -> bytes:
        nonce = Base64Encoder.decode(payload['nonce'].encode())
        ciphertext = Base64Encoder.decode(payload['payload'].encode())
        return self.secret_box.decrypt(ciphertext, nonce=nonce)

    def pub_encrypt(self, plaintext: bytes) -> bytes:
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        payload = self.box.encrypt(plaintext, nonce=nonce, encoder=Base64Encoder)
        return payload

    def from_symm_to_pub(self, payload: Dict[Any, Any]) -> bytes:
        plaintext = self.symm_decrypt(payload)
        return self.pub_encrypt(plaintext)
