# pylint: disable=c-extension-no-member

from dependency_injector import containers, providers

from app.services.encryption.jwt_service_factory import JWTServiceFactory
from app.services.encryption.rsa_jwe_service import RSAJweService
from app.services.encryption.sym_encryption_service import SymEncryptionService


class EncryptionServices(containers.DeclarativeContainer):
    config = providers.Configuration()

    user_authentication_encryption_service = providers.Singleton(
        SymEncryptionService, raw_local_sym_key=config.app.user_authentication_sym_key
    )

    jwe_service = providers.Singleton(
        RSAJweService,
        jwe_sign_priv_key_path=config.jwe.jwe_sign_priv_key_path,
        jwe_sign_crt_path=config.jwe.jwe_sign_crt_path,
    )

    jwt_service_factory = providers.Singleton(JWTServiceFactory)
