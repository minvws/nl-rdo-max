# pylint: disable=c-extension-no-member, too-few-public-methods

from dependency_injector import containers, providers

from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.encryption.xed25519_jwe_service import XEd25519JweService
from app.services.encryption.rsa_jwe_service import RSAJweService
from app.services.encryption.sym_encryption_service import SymEncryptionService


class EncryptionServices(containers.DeclarativeContainer):
    config = providers.Configuration()

    user_authentication_encryption_service = providers.Singleton(
        SymEncryptionService, raw_local_sym_key=config.app.user_authentication_sym_key
    )
    _ed25519_jwe_service = providers.Singleton(
        XEd25519JweService, raw_sign_key=config.app.jwe_sign_nacl_priv_key
    )

    _rsa_jwe_service = providers.Singleton(
        RSAJweService,
        jwe_sign_priv_key_path=config.app.jwe_sign_priv_key_path,
        jwe_sign_crt_path=config.app.jwe_sign_crt_path,
    )

    jwe_service_provider = providers.Singleton(
        JweServiceProvider, rsa=_rsa_jwe_service, x25519=_ed25519_jwe_service
    )
