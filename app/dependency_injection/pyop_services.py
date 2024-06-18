# pylint: disable=c-extension-no-member, too-few-public-methods
from typing import List

from dependency_injector import containers, providers
from dependency_injector.providers import Singleton
from jwkest.jwk import RSAKey, import_rsa_key
from pyop.authz_state import AuthorizationState
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

from app.misc.utils import (
    as_list,
    clients_from_json,
    kid_from_certificate,
    file_content_raise_if_none,
)
from app.providers.pyop_provider import MaxPyopProvider
from app.providers.saml_provider import SAMLProvider


def pyop_rsa_signing_key_callable(signing_key_path: str, signing_key_crt_path: str):
    signing_key = file_content_raise_if_none(signing_key_path)
    signing_key_crt = file_content_raise_if_none(signing_key_crt_path)
    kid = kid_from_certificate(signing_key_crt)
    key = RSAKey(key=import_rsa_key(signing_key), alg="RS256")
    key.kid = kid
    return key


def pyop_configuration_information_callable(
    issuer: str,
    authorize_endpoint: str,
    jwks_endpoint: str,
    token_endpoint: str,
    userinfo_endpoint: str,
    scopes_supported: List[str],
):
    return {
        "issuer": issuer,
        "authorization_endpoint": issuer + authorize_endpoint,
        "jwks_uri": issuer + jwks_endpoint,
        "token_endpoint": issuer + token_endpoint,
        "scopes_supported": scopes_supported,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["pairwise"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "claims_parameter_supported": True,
        "userinfo_endpoint": issuer + userinfo_endpoint,
    }


class PyopServices(containers.DeclarativeContainer):
    config = providers.Configuration()

    storage = providers.DependenciesContainer()

    pyop_rsa_signing_key = providers.Callable(
        pyop_rsa_signing_key_callable,
        signing_key_path=config.oidc.rsa_private_key,
        signing_key_crt_path=config.oidc.rsa_private_key_crt,
    )

    pyop_configuration_information = providers.Callable(
        pyop_configuration_information_callable,
        issuer=config.oidc.issuer,
        authorize_endpoint=config.oidc.authorize_endpoint,
        jwks_endpoint=config.oidc.jwks_endpoint,
        token_endpoint=config.oidc.accesstoken_endpoint,
        userinfo_endpoint=config.oidc.userinfo_endpoint,
        scopes_supported=config.oidc.scopes_supported.as_(as_list),
    )

    subject_identifier_factory = providers.Singleton(
        HashBasedSubjectIdentifierFactory, config.oidc.subject_id_hash_salt
    )  # type: Singleton[HashBasedSubjectIdentifierFactory]

    authz_state = providers.Singleton(
        AuthorizationState,
        subject_identifier_factory=subject_identifier_factory,
        authorization_code_db=storage.authorization_code_db,
        access_token_db=storage.authorization_code_db,
        refresh_token_db=storage.access_token_db,
        subject_identifier_db=storage.subject_identifier_db,
    )  # type: Singleton[AuthorizationState]

    saml_provider = providers.Singleton(SAMLProvider)

    clients = config.oidc.clients_file.as_(clients_from_json)

    pyop_provider = providers.Singleton(
        MaxPyopProvider,
        signing_key=pyop_rsa_signing_key,
        configuration_information=pyop_configuration_information,
        authz_state=authz_state,
        clients=clients,
        userinfo=Userinfo({"_": {}}),
        id_token_lifetime=config.redis.object_ttl.as_int(),
        trusted_certificates_directory=config.oidc.certificates_directory,
    )
