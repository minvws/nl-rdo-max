import base64
import json

from typing import Dict, Any

from OpenSSL.crypto import load_certificate, FILETYPE_PEM

import nacl.utils
from nacl.secret import SecretBox
from nacl.public import PrivateKey, Box, PublicKey
from nacl.encoding import Base64Encoder

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from jwcrypto.jwt import JWT, JWK

def get_pem_from_nacl(nacl_key):
    cryptography_signkey = Ed25519PrivateKey.from_private_bytes(bytes(nacl_key))
    return cryptography_signkey.private_bytes(
        encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )

class Encrypt:
    def __init__(
        self, raw_sign_key: bytes, raw_sign_pubkey: bytes, raw_enc_key: bytes, raw_local_enc_key: str
    ) -> None:
        sign_key = PrivateKey(raw_sign_key, encoder=Base64Encoder)
        sign_pubkey = PublicKey(raw_sign_pubkey, encoder=Base64Encoder)
        enc_key = PublicKey(raw_enc_key, encoder=Base64Encoder)

        self.box = Box(sign_key, enc_key)
        self.secret_box = SecretBox(bytes.fromhex(raw_local_enc_key))

        sign_key_pem = get_pem_from_nacl(sign_key)
        sign_pubkey_pem = get_pem_from_nacl(sign_pubkey)
        enc_key_pem = get_pem_from_nacl(enc_key)

        jwk_sign_pub = JWK.from_pem(sign_pubkey_pem)

        self.jwk_sign = JWK.from_pem(sign_key_pem)
        self.jwk_enc = JWK.from_pem(enc_key_pem)

        self.fingerprint_enc = self.jwk_enc.thumbprint()
        self.fingerprint_sign = jwk_sign_pub.thumbprint()

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
            "alg": "RS256",
            "x5t": self.fingerprint_sign
        }, claims=data)

        jws_token.make_signed_token(self.jwk_sign)

        etoken = JWT(header={
                'typ': "JWT",
                'cty': "JWT",
                'alg': "RSA-OAEP",
                'enc': "A128CBC-HS256",
                'x5t': self.fingerprint_enc
        }, claims=jws_token.serialize())

        etoken.make_encrypted_token(self.jwk_enc)
        return etoken.serialize()
