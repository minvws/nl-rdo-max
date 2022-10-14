from typing import Dict, Any, Union
from jwcrypto.jwt import JWK, JWT

from app.misc.utils import file_content, get_fingerprint
from app.services.encryption.jwe_service import JweService


class RsaJweService(JweService):
    def __init__(
            self,
            jwe_sign_priv_key_path: str,
            jwe_sign_crt_path: str
    ):
        self._jwe_sign_priv_key = file_content(jwe_sign_priv_key_path)
        self._jwe_sign_crt_path = file_content(jwe_sign_crt_path)
        self._jwk_sign_key = JWK.from_pem(self._jwe_sign_priv_key.encode())

    def to_jwe(self, data: Dict[Any, Any], pubkey: Union[str, None] = None) -> str:
        if pubkey is None:
            raise Exception("No pubkey configured for client")
        header = {
            "typ": "JWT",
            "cty": "JWT",
            "alg": "RSA-OAEP",
            "enc": "A128CBC-HS256",
            "x5t": get_fingerprint(pubkey.encode("utf-8")).decode(),
        }
        jwk_uzipas_enc = JWK.from_pem(pubkey.encode())
        crt = JWK.from_pem(str.encode(self._jwe_sign_crt_path))

        jwt_token = JWT(
            {
                "alg": "RS256",
                "x5t": get_fingerprint(self._jwe_sign_crt_path.encode("utf-8")).decode(),
                "kid": crt.kid
            },
            claims=data,
        )
        jwt_token.make_signed_token(self._jwk_sign_key)
        etoken = JWT(header=header, claims=jwt_token.serialize())
        etoken.make_encrypted_token(jwk_uzipas_enc)
        return etoken.serialize()
