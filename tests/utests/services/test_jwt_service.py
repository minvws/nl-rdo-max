from configparser import ConfigParser

from app.misc.utils import load_jwk
from app.services.encryption.jwt_service import JWTService
from app.services.encryption.jwt_service_factory import JWTServiceFactory


CONFIG = ConfigParser()
CONFIG.read("tests/max.test.conf")

MOCK_PRIVATE_KEY_PATH = CONFIG.get("jwt", "session_jwt_sign_priv_key_path")
MOCK_CERTIFICATE_PATH = CONFIG.get("jwt", "session_jwt_sign_crt_path")


def create_jwt_service() -> JWTService:
    return JWTServiceFactory.create(
        jwt_private_key_path=MOCK_PRIVATE_KEY_PATH,
        jwt_signing_certificate_path=MOCK_CERTIFICATE_PATH,
    )


def test_jwt_service_factory() -> None:
    jwt_service = create_jwt_service()
    assert isinstance(jwt_service, JWTService)


def test_from_jwt() -> None:
    jwt_service = create_jwt_service()
    expected_claims = {"claims": "some example data"}
    mock_public_key = load_jwk(MOCK_PRIVATE_KEY_PATH)

    jwt_token = jwt_service.create_jwt(expected_claims)
    actual_claims = jwt_service.from_jwt(mock_public_key, jwt_token)

    assert actual_claims["claims"] == expected_claims["claims"]


def test_from_jwe() -> None:
    jwt_service = create_jwt_service()
    expected_claims = {"claims": "some example data"}
    mock_public_key = load_jwk(MOCK_PRIVATE_KEY_PATH)

    jwe_token = jwt_service.create_jwe(mock_public_key, expected_claims)
    actual_claims = jwt_service.from_jwe(mock_public_key, jwe_token)

    assert actual_claims["claims"] == expected_claims["claims"]
