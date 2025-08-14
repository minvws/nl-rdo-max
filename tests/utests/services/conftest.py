from typing import Tuple

import pytest
from jwcrypto.jwk import JWK

from app.models.certificate_with_jwk import CertificateWithJWK
from app.services.encryption.jwt_service import JWTService
from tests.utils import make_test_certificate


@pytest.fixture
def session_jwt_issuer() -> str:
    return "max-test-issuer"


@pytest.fixture
def session_jwt_sign_certificate_with_key() -> Tuple[CertificateWithJWK, JWK]:
    return make_test_certificate()


@pytest.fixture
def session_jwt_sign_certificate(
    session_jwt_sign_certificate_with_key,
) -> CertificateWithJWK:
    certificate, private_key = session_jwt_sign_certificate_with_key
    return certificate


@pytest.fixture
def session_jwt_sign_priv_key(session_jwt_sign_certificate_with_key) -> JWK:
    certificate, private_key = session_jwt_sign_certificate_with_key
    return private_key


@pytest.fixture
def jwt_service(
    session_jwt_issuer, session_jwt_sign_priv_key, session_jwt_sign_certificate
) -> JWTService:
    return JWTService(
        issuer=session_jwt_issuer,
        signing_private_key=session_jwt_sign_priv_key,
        signing_certificate=session_jwt_sign_certificate,
    )
