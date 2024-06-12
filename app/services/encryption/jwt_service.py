import json
import logging
import time
from typing import Dict, Any

from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from cryptography.hazmat.primitives import hashes

from app.misc.utils import file_content_raise_if_none

JWT_EXP_MARGIN = 60

JWT_NBF_MARGIN = 10

JWT_ALG = "RS256"

logger = logging.getLogger(__name__)


class JWTService:
    _jwt_private_key: JWK
    _certificate_kid: JWK

    def __init__(self, jwt_private_key_path: str, certificate_kid_path: str) -> None:
        self._jwt_private_key = JWK.from_pem(
            file_content_raise_if_none(jwt_private_key_path).encode("utf-8")
        )
        self._certificate_kid = JWK.from_pem(
            file_content_raise_if_none(certificate_kid_path).encode("utf-8")
        )

    def create_jwt(self, payload: Dict[str, Any]) -> str:
        # temporary type ignore
        return create_jwt(self._jwt_private_key, self._certificate_kid, payload)  # type: ignore

    def from_jwt(self, jwt_pub_key: JWK, jwt: str) -> Dict[str, Any]:
        return from_jwt(jwt_pub_key, jwt)


def from_jwt(jwt_public_key: JWK, jwt_string: str) -> Dict[str, Any]:
    jwt = JWT.from_jose_token(jwt_string)
    jwt.validate(jwt_public_key)
    return json.loads(jwt.claims)


def create_jwt(
    jwt_private_key: JWK,
    certificate_kid: str,
    payload: Dict[str, Any],
) -> str:
    jwt_header = {
        "alg": JWT_ALG,
        "x5t": jwt_private_key.thumbprint(hashes.SHA256()),
        "kid": certificate_kid,
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
    jwt_token.make_signed_token(jwt_private_key)
    return jwt_token.serialize()
