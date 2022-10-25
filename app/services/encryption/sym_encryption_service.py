# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
# todo: Add copyright to every file
import base64
import json

import nacl.utils
from nacl.secret import SecretBox
from nacl.encoding import Base64Encoder


class SymEncryptionService:
    def __init__(self, raw_local_sym_key: str) -> None:
        self.secret_box = SecretBox(bytes.fromhex(raw_local_sym_key))

    def symm_encrypt(self, data: bytes) -> bytes:
        nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        encrypted_msg = self.secret_box.encrypt(data, nonce=nonce)
        payload = {
            "payload": Base64Encoder.encode(encrypted_msg.ciphertext).decode(),
            "nonce": Base64Encoder.encode(encrypted_msg.nonce).decode(),
        }
        return base64.b64encode(json.dumps(payload).encode())

    def symm_decrypt(self, payload: bytes) -> bytes:
        decoded_payload = json.loads(base64.b64decode(payload).decode())
        nonce = Base64Encoder.decode(decoded_payload["nonce"].encode())
        ciphertext = Base64Encoder.decode(decoded_payload["payload"].encode())
        return self.secret_box.decrypt(ciphertext, nonce=nonce)
