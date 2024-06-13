from app.misc.utils import load_jwk, file_content_raise_if_none, kid_from_certificate
from app.services.encryption.jwt_service import JWTService


class JWTServiceFactory:
    @staticmethod
    def create(
        jwt_private_key_path: str, jwt_signing_certificate_path: str
    ) -> JWTService:
        private_key = load_jwk(jwt_private_key_path)
        certificate = file_content_raise_if_none(jwt_signing_certificate_path)
        certificate_kid = kid_from_certificate(certificate)
        return JWTService(jwt_priv_key=private_key, crt_kid=certificate_kid)
