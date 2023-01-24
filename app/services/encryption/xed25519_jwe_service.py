# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
import base64
import json
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey,
    X25519PrivateKey,
)
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey, Box, PublicKey

from app.services.encryption.jwe_service import JweService


def _create_x25519_pubkey(key):
    """
    JWCrypto does not directly support X25519 keys, this helper class is similiar to
    JWK.from_pyca(), and allows to import the x25519 pubkey. However, access to a protected
    method is required.
    """
    jwk = JWK()
    jwk._import_pyca_pub_okp(key)  # pylint: disable=protected-access
    return jwk


class XEd25519JweService(JweService):
    def __init__(self, raw_sign_key: str):
        sign_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(raw_sign_key))
        self._nacl_box_encrypt_key = PrivateKey(
            raw_sign_key.encode("utf-8"), encoder=Base64Encoder
        )
        self._private_sign_jwk_key = JWK.from_pyca(sign_key)
        self._public_sign_jwk_key = JWK.from_pyca(sign_key.public_key())

    def get_pub_jwk(self) -> JWK:
        return self._public_sign_jwk_key

    def to_jwe(self, data: Dict[str, Any], pubkey: str) -> str:
        jwk_enc = _create_x25519_pubkey(
            X25519PublicKey.from_public_bytes(base64.b64decode(pubkey.encode("utf-8")))
        )
        jws_token = JWT(
            {
                "alg": "EdDSA",
            },
            claims=data,
        )
        jws_token.make_signed_token(self._private_sign_jwk_key)
        jws_token.validate(self._public_sign_jwk_key)
        etoken = JWT(
            header={"typ": "JWT", "alg": "ECDH-ES", "enc": "A128CBC-HS256"},
            claims=jws_token.serialize(),
        )
        etoken.make_encrypted_token(jwk_enc)
        return etoken.serialize()

    def from_jwe(self, jwe_str: str, privkey: str) -> Dict[str, Any]:
        jwe = JWE.from_jose_token(jwe_str)
        jwk = JWK()
        # noinspection PyProtectedMember
        jwk._import_pyca_pri_okp(  # pylint: disable=protected-access
            X25519PrivateKey.from_private_bytes(base64.b64decode(privkey))
        )
        jwe.decrypt(jwk)
        jwt = JWT.from_jose_token(jwe.payload.decode("utf-8"))
        jwt.validate(self._public_sign_jwk_key)
        return json.loads(jwt.claims)

    def box_encrypt(self, data: str, client_key: str) -> str:
        enc_key = PublicKey(client_key.encode("utf-8"), encoder=Base64Encoder)
        box = Box(self._nacl_box_encrypt_key, enc_key)
        return box.encrypt(data.encode("utf-8"), encoder=Base64Encoder).decode("utf-8")
