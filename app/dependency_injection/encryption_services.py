# pylint: disable=c-extension-no-member

from dependency_injector import containers, providers

from app.misc.utils import load_jwk, load_certificate_with_jwk_from_path
from app.services.encryption.jwt_service import JWTService
from app.services.encryption.sym_encryption_service import SymEncryptionService


class EncryptionServices(containers.DeclarativeContainer):
    config = providers.Configuration()

    user_authentication_encryption_service = providers.Singleton(
        SymEncryptionService, raw_local_sym_key=config.app.user_authentication_sym_key
    )

    jwt_service = providers.Singleton(
        JWTService,
        issuer=config.oidc.issuer,
        signing_private_key=config.jwe.jwe_sign_priv_key_path.as_(load_jwk),
        signing_certificate=config.jwe.jwe_sign_crt_path.as_(
            load_certificate_with_jwk_from_path
        ),
        exp_margin=config.oidc.jwt_expiration_duration.as_int(),
        nbf_margin=config.oidc.jwt_nbf_lag.as_int(),
    )
