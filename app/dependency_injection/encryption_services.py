# pylint: disable=c-extension-no-member, too-few-public-methods

from dependency_injector import containers, providers

from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.encryption.sym_encryption_service import SymEncryptionService


class EncryptionServices(containers.DeclarativeContainer):
    config = providers.Configuration()

    user_authentication_encryption_service = providers.Singleton(
        SymEncryptionService, raw_local_sym_key=config.app.user_authentication_sym_key
    )

    jwe_service_provider = providers.Singleton(
        JweServiceProvider,
        config=config.jwe,
    )
