import json
from typing import Dict, Any

from cryptography.hazmat.primitives import hashes
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from app.misc.utils import file_content_raise_if_none, kid_from_certificate
from app.services.encryption.jwe_service import JweService


class RSAJweService(JweService):
    def __init__(self, jwe_sign_priv_key_path: str, jwe_sign_crt_path: str):
        jwe_sign_priv_key = file_content_raise_if_none(jwe_sign_priv_key_path)
        jwe_sign_crt = file_content_raise_if_none(jwe_sign_crt_path)
        self._private_sign_jwk_key = JWK.from_pem(jwe_sign_priv_key.encode("utf-8"))
        self._public_sign_jwk_key = JWK.from_pem(jwe_sign_crt.encode("utf-8"))
        self._jwe_sign_crt_kid = kid_from_certificate(jwe_sign_crt)

    def get_pub_jwk(self) -> JWK:
        return self._public_sign_jwk_key

    def to_jwe(self, data: Dict[str, Any], pubkey: str) -> str:
        header = {
            "typ": "JWT",
            "cty": "JWT",
            "alg": "RSA-OAEP",
            "enc": "A128CBC-HS256",
            "x5t": self._private_sign_jwk_key.thumbprint(hashes.SHA256()),
        }

        jwt_token = JWT(
            {
                "alg": "RS256",
                "x5t": self._private_sign_jwk_key.thumbprint(hashes.SHA256()),
                "kid": self._jwe_sign_crt_kid,
            },
            claims=data,
        )

        jwt_token.make_signed_token(self._private_sign_jwk_key)
        etoken = JWT(header=header, claims=jwt_token.serialize())
        etoken.make_encrypted_token(JWK.from_pem(pubkey.encode("utf-8")))
        return etoken.serialize()

    def from_jwe(self, jwe_str: str, privkey: str) -> Dict[str, Any]:
        jwe = JWE.from_jose_token(jwe_str)
        jwk = JWK.from_pem(privkey.encode("utf-8"))
        jwe.decrypt(jwk)
        jwt = JWT.from_jose_token(jwe.payload.decode("utf-8"))
        jwt.validate(self._public_sign_jwk_key)
        return json.loads(jwt.claims)
