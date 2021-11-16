import base64
import json

from typing import Dict, Any

import nacl.utils
from nacl.secret import SecretBox
from nacl.public import PrivateKey, Box, PublicKey
from nacl.encoding import Base64Encoder

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from jwcrypto.jwt import JWT, JWK


def _create_x25519_pubkey(key):
    jwk = JWK()
    jwk._import_pyca_pub_okp(key)
    return jwk

class Encrypt:
    def __init__(
        self, raw_sign_key: bytes, raw_enc_key: bytes, raw_local_enc_key: str
    ) -> None:
        sign_key = PrivateKey(raw_sign_key, encoder=Base64Encoder)
        enc_key = PublicKey(raw_enc_key, encoder=Base64Encoder)

        self.box = Box(sign_key, enc_key)
        self.secret_box = SecretBox(bytes.fromhex(raw_local_enc_key))

        self.jwk_sign = JWK.from_pyca(Ed25519PrivateKey.from_private_bytes(bytes(sign_key)))
        self.jwk_enc = _create_x25519_pubkey(X25519PublicKey.from_public_bytes(bytes(enc_key)))

    def symm_encrypt(self, data: Dict[str, Any]) -> bytes:
        plaintext = base64.b64encode(json.dumps(data).encode())
        nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
        encrypted_msg = self.secret_box.encrypt(plaintext, nonce=nonce)
        payload = {
            "payload": Base64Encoder.encode(encrypted_msg.ciphertext).decode(),
            "nonce": Base64Encoder.encode(encrypted_msg.nonce).decode(),
        }
        return base64.b64encode(json.dumps(payload).encode())

    def symm_decrypt(self, payload: bytes) -> Dict[str, Any]:
        decoded_payload = json.loads(base64.b64decode(payload).decode())
        nonce = Base64Encoder.decode(decoded_payload["nonce"].encode())
        ciphertext = Base64Encoder.decode(decoded_payload["payload"].encode())
        encoded_data = self.secret_box.decrypt(ciphertext, nonce=nonce)
        return json.loads(base64.b64decode(encoded_data).decode())

    def pub_encrypt(self, data: Dict[str, Any]) -> bytes:
        plaintext = base64.b64encode(json.dumps(data).encode())
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        payload = self.box.encrypt(plaintext, nonce=nonce, encoder=Base64Encoder)
        return payload

    def from_symm_to_pub(self, payload: Dict[Any, Any]) -> bytes:
        data = self.symm_decrypt(payload)
        return self.pub_encrypt(data)

    def from_symm_to_jwt(self, payload: Dict[Any, Any]) -> bytes:
        data = self.symm_decrypt(payload)
        return self.to_jwe(data)

    def to_jwe(self, data: Dict[Any, Any]) -> bytes:
        jws_token = JWT({
            "alg": "EdDSA",
        }, claims=data)

        jws_token.make_signed_token(self.jwk_sign)

        etoken = JWT(header={
                'typ': "JWT",
                'alg': "ECDH-ES",
                'enc': "A128CBC-HS256"
        }, claims=jws_token.serialize())

        etoken.make_encrypted_token(self.jwk_enc)
        return etoken.serialize()
