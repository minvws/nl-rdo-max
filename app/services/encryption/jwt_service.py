import json
import logging
import time
from typing import Any, Dict, Optional

from jwcrypto.jwe import JWE
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from jwcrypto.common import JWException

from app.models.certificate_with_jwk import CertificateWithJWK

JWT_EXP_MARGIN = 60
JWT_NBF_MARGIN = 10

JWE_ENC = "A128CBC-HS256"
JWE_ALG = "RSA-OAEP"
JWE_CTY = "JWT"
JWE_TYP = "JWT"
JWT_ALG = "RS256"

logger = logging.getLogger(__name__)


class JWTService:
    def __init__(
        self,
        issuer: str,
        signing_private_key: JWK,
        signing_certificate: CertificateWithJWK,
        exp_margin: int = JWT_EXP_MARGIN,
        nbf_margin: int = JWT_NBF_MARGIN,
    ) -> None:
        self.__signing_private_key = signing_private_key
        self._signing_certificate = signing_certificate
        self.issuer = issuer
        self.exp_margin = exp_margin
        self.nbf_margin = nbf_margin

    def get_signing_certificate(self) -> CertificateWithJWK:
        return self._signing_certificate

    def create_jwt(self, payload: Dict[str, Any]) -> str:
        return create_jwt(
            issuer=self.issuer,
            signing_private_key=self.__signing_private_key,
            signing_certificate=self._signing_certificate,
            payload=payload,
            exp_margin=self.exp_margin,
            nbf_margin=self.nbf_margin,
        )

    def create_jwe(
        self, encryption_certificate: CertificateWithJWK, payload: Dict[str, Any]
    ) -> str:
        return create_jwe(
            issuer=self.issuer,
            private_key=self.__signing_private_key,
            signing_certificate=self._signing_certificate,
            encryption_certificate=encryption_certificate,
            payload=payload,
            exp_margin=self.exp_margin,
            nbf_margin=self.nbf_margin,
        )

    def from_jwe(self, jwt_pub_key: JWK, jwe: str) -> Optional[Dict[str, Any]]:
        return from_jwe(self.__signing_private_key, jwt_pub_key, jwe)


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
    private_key: JWK, jwt_pub_key: JWK, jwe_str: str
) -> Optional[Dict[str, Any]]:
    jwe = JWE.from_jose_token(jwe_str)
    jwe.decrypt(private_key)
    return from_jwt(jwt_pub_key, jwe.payload.decode("utf-8"))


def create_jwt(
    issuer: str,
    signing_private_key: JWK,
    signing_certificate: CertificateWithJWK,
    payload: Dict[str, Any],
    nbf_margin: int = JWT_NBF_MARGIN,
    exp_margin: int = JWT_EXP_MARGIN,
) -> str:
    jwt_header = {
        "alg": JWT_ALG,
        "x5t": signing_certificate.x5t,
        "kid": signing_certificate.kid,
    }
    now = int(time.time())
    jwt_payload = {
        **{
            "iss": issuer,
            "nbf": now - nbf_margin,
            "exp": now + exp_margin,
        },
        **payload,
    }
    jwt_token = JWT(
        header=jwt_header,
        claims=jwt_payload,
    )
    jwt_token.make_signed_token(signing_private_key)
    return jwt_token.serialize()


def create_jwe(
    issuer: str,
    private_key: JWK,
    signing_certificate: CertificateWithJWK,
    encryption_certificate: CertificateWithJWK,
    payload: Dict[str, Any],
    nbf_margin: int = JWT_NBF_MARGIN,
    exp_margin: int = JWT_EXP_MARGIN,
) -> str:
    jwt_token = create_jwt(
        issuer=issuer,
        signing_private_key=private_key,
        signing_certificate=signing_certificate,
        payload=payload,
        nbf_margin=nbf_margin,
        exp_margin=exp_margin,
    )
    jwe_header = {
        "typ": JWE_TYP,
        "cty": JWE_CTY,
        "alg": JWE_ALG,
        "enc": JWE_ENC,
        "x5t": encryption_certificate.x5t,
    }
    jwe_token = JWT(header=jwe_header, claims=jwt_token)
    jwe_token.make_encrypted_token(encryption_certificate.jwk)
    return jwe_token.serialize()
