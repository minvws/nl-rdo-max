import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
    X25519PrivateKey,
)
import cryptography.hazmat.primitives.serialization

from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from jwcrypto.jwe import JWE
from nacl.signing import SigningKey
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder

from app.services.encryption.xed25519_jwe_service import XEd25519JweService


def test_to_jwe():
    server_signing_key = SigningKey.generate()
    server_pub_key = server_signing_key.verify_key
    client_priv_key = PrivateKey.generate()
    client_pub_key = client_priv_key.public_key

    server_pub_key_hazmat = Ed25519PublicKey.from_public_bytes(bytes(server_pub_key))

    encryption_service = XEd25519JweService(
        raw_sign_key=server_signing_key.encode(encoder=Base64Encoder).decode("utf-8")
    )
    actual_jwe = encryption_service.to_jwe(
        {"key": "value"}, client_pub_key.encode(encoder=Base64Encoder).decode("utf-8")
    )
    jwe = JWE.from_jose_token(actual_jwe)
    jwk = JWK()
    client_priv_key_hazmat = X25519PrivateKey.from_private_bytes(bytes(client_priv_key))
    jwk._import_pyca_pri_okp(client_priv_key_hazmat)
    jwe.decrypt(jwk)
    jwt = JWT.from_jose_token(jwe.payload.decode("utf-8"))
    jwt.validate(JWK.from_pyca(server_pub_key_hazmat))
    jwt.validate(encryption_service.get_pub_jwk())
    assert jwt.claims == '{"key":"value"}'
