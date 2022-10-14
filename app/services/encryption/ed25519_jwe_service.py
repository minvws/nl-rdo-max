# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
from typing import Dict, Any, Union

from nacl.public import PrivateKey, Box, PublicKey
from nacl.encoding import Base64Encoder

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK

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
    def __init__(self, raw_sign_key: bytes, raw_enc_key: bytes):
        sign_key = PrivateKey(raw_sign_key, encoder=Base64Encoder)
        enc_key = PublicKey(raw_enc_key, encoder=Base64Encoder)
        self.jwk_sign = JWK.from_pyca(
            Ed25519PrivateKey.from_private_bytes(bytes(sign_key))
        )
        self.jwk_enc = _create_x25519_pubkey(
            X25519PublicKey.from_public_bytes(bytes(enc_key))
        )

    def to_jwe(self, data: Dict[Any, Any], _: Union[str, None] = None) -> str:
        jws_token = JWT(
            {
                "alg": "EdDSA",
            },
            claims=data,
        )
        jws_token.make_signed_token(self.jwk_sign)
        etoken = JWT(
            header={"typ": "JWT", "alg": "ECDH-ES", "enc": "A128CBC-HS256"},
            claims=jws_token.serialize(),
        )
        etoken.make_encrypted_token(self.jwk_enc)
        return etoken.serialize()