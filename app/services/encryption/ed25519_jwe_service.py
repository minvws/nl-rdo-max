# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
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


class Ed25519JweService(JweService):
    def __init__(self, raw_sign_key: bytes):
        self._sign_key = PrivateKey(raw_sign_key, encoder=Base64Encoder)
        self._jwk_sign = JWK.from_pyca(
            Ed25519PrivateKey.from_private_bytes(bytes(self._sign_key))
        )

    def to_jwe(self, data: Dict[str, Any], pubkey: str) -> str:
        jwk_enc = _create_x25519_pubkey(
            X25519PublicKey.from_public_bytes(bytes(pubkey.encode("utf-8")))
        )
        jws_token = JWT(
            {
                "alg": "EdDSA",
            },
            claims=data,
        )
        jws_token.make_signed_token(self._jwk_sign)
        etoken = JWT(
            header={"typ": "JWT", "alg": "ECDH-ES", "enc": "A128CBC-HS256"},
            claims=jws_token.serialize(),
        )
        etoken.make_encrypted_token(jwk_enc)
        return etoken.serialize()

    def box_encrypt(self, data: str, client_key: str) -> str:
        enc_key = PublicKey(client_key.encode("utf-8"), encoder=Base64Encoder)
        box = Box(self._sign_key, enc_key)
        return box.encrypt(data.encode("utf-8"), encoder=Base64Encoder).decode("utf-8")
