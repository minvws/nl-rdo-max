import json
import logging
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from jwcrypto.common import JWException

JWT_EXP_MARGIN = 60

JWT_NBF_MARGIN = 10

JWE_ENC = "A128CBC-HS256"
JWE_ALG = "RSA-OAEP"
JWE_CTY = "JWT"
JWE_TYP = "JWT"
JWT_ALG = "RS256"

logger = logging.getLogger(__name__)


class JWTService:
    def __init__(self, jwt_priv_key: JWK, crt_kid: str) -> None:
        self._jwt_priv_key = jwt_priv_key
        self._crt_kid = crt_kid

    def create_jwt(self, payload: Dict[str, Any]) -> str:
        return create_jwt(self._jwt_priv_key, self._crt_kid, payload)

    def create_jwe(self, jwe_enc_pub_key: JWK, payload: Dict[str, Any]) -> str:
        return create_jwe(self._jwt_priv_key, self._crt_kid, jwe_enc_pub_key, payload)

    def from_jwt(
        self, jwt_pub_key: JWK, jwt: str, check_claims: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        return from_jwt(jwt_pub_key, jwt, check_claims)

    def from_jwe(self, jwt_pub_key: JWK, jwe: str) -> Optional[Dict[str, Any]]:
        return from_jwe(self._jwt_priv_key, jwt_pub_key, jwe)


def from_jwt(
    jwt_pub_key: JWK, jwt_str: str, check_claims: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    try:
        jwt = JWT(
            jwt=jwt_str,
            key=jwt_pub_key,
            check_claims=check_claims,
        )
        jwt.validate(jwt_pub_key)
        return json.loads(jwt.claims)
    except (JWException, ValueError) as exception:
        logger.error(exception)
        return None


def from_jwe(
    jwt_priv_key: JWK, jwt_pub_key: JWK, jwe_str: str
) -> Optional[Dict[str, Any]]:
    jwe = JWE.from_jose_token(jwe_str)
    jwe.decrypt(jwt_priv_key)
    return from_jwt(jwt_pub_key, jwe.payload.decode("utf-8"))


def create_jwt(
    jwt_priv_key: JWK,
    crt_kid: str,
    payload: Dict[str, Any],
) -> str:
    jwt_header = {
        "alg": JWT_ALG,
        "x5t": jwt_priv_key.thumbprint(hashes.SHA256()),
        "kid": crt_kid,
    }
    jwt_payload = {
        **{
            "nbf": int(time.time()) - JWT_NBF_MARGIN,
            "exp": int(time.time()) + JWT_EXP_MARGIN,
        },
        **payload,
    }
    jwt_token = JWT(
        header=jwt_header,
        claims=jwt_payload,
    )
    jwt_token.make_signed_token(jwt_priv_key)
    return jwt_token.serialize()


def create_jwe(
    jwt_priv_key: JWK,
    crt_kid: str,
    jwe_enc_pub_key: JWK,
    payload: Dict[str, Any],
) -> str:
    jwt_token = create_jwt(jwt_priv_key, crt_kid, payload)
    jwe_header = {
        "typ": JWE_TYP,
        "cty": JWE_CTY,
        "alg": JWE_ALG,
        "enc": JWE_ENC,
        "x5t": jwt_priv_key.thumbprint(hashes.SHA256()),
    }

    jwe_token = JWT(header=jwe_header, claims=jwt_token)
    jwe_token.make_encrypted_token(jwe_enc_pub_key)
    return jwe_token.serialize()
