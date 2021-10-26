from typing import Any
import json

from jwkest.jwk import RSAKey, rsa_load

from pyop.authz_state import AuthorizationState
from pyop.provider import Provider as PyopProvider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

from ..config import Settings
from ..cache import RedisCache
from .storage import RedisWrapper

# pylint: disable=too-few-public-methods
class Provider:
    """
    OIDC provider configuration. Allowing to handle authorize requests and supply JWT tokens.

    Required settings:
        - settings.issuer
        - settings.authorize_endpoint
        - settings.jwks_endpoint
        - settings.accesstoken_endpoint

        - settings.oidc.rsa_private_key
        - settings.oidc.rsa_public_key
        - settings.oidc.subject_id_hash_salt
        - settings.oidc.id_token_lifetime

        - settings.redis.host
        - settings.redis.port
        - settings.redis.code_namespace
        - settings.redis.token_namespace
        - settings.redis.refresh_token_namespace
        - settings.redis.sub_id_namespace
    """

    def __init__(self, settings: Settings ) -> None:
        self.redis_ttl = int(settings.redis.object_ttl)

        self.redis_cache = RedisCache(settings=settings)
        self.redis_client = self.redis_cache.redis_client

        issuer = settings.issuer
        authentication_endpoint = settings.authorize_endpoint
        jwks_uri = settings.jwks_endpoint
        token_endpoint = settings.accesstoken_endpoint

        configuration_information = {
            'issuer': issuer,
            'authorization_endpoint': issuer + authentication_endpoint,
            'jwks_uri': issuer + jwks_uri,
            'token_endpoint': issuer + token_endpoint,
            'scopes_supported': ['openid'],
            'response_types_supported': ['code'],
            'response_modes_supported': ['query'],
            'grant_types_supported': ['authorization_code'],
            'subject_types_supported': ['pairwise'],
            'token_endpoint_auth_methods_supported': ['none'],
            'claims_parameter_supported': True
        }

        userinfo_db = Userinfo({'test_client': {'test': 'test_client'}})
        with open(settings.oidc.clients_file, 'r', encoding='utf-8') as clients_file:
            clients = json.load(clients_file)

        signing_key = RSAKey(key=rsa_load(settings.oidc.rsa_private_key), alg='RS256', )

        authorization_code_db = RedisWrapper(redis_client=self.redis_client, collection=settings.redis.code_namespace, ttl=self.redis_ttl)
        access_token_db = RedisWrapper(redis_client=self.redis_client, collection=settings.redis.token_namespace, ttl=self.redis_ttl)
        refresh_token_db = RedisWrapper(redis_client=self.redis_client, collection=settings.redis.refresh_token_namespace, ttl=self.redis_ttl)
        subject_identifier_db = RedisWrapper(redis_client=self.redis_client, collection=settings.redis.sub_id_namespace, ttl=self.redis_ttl)

        authz_state = AuthorizationState(
            HashBasedSubjectIdentifierFactory(settings.oidc.subject_id_hash_salt),
            authorization_code_db=authorization_code_db,
            access_token_db=access_token_db,
            refresh_token_db=refresh_token_db,
            subject_identifier_db=subject_identifier_db
        )

        self.provider = PyopProvider(signing_key, configuration_information,
                            authz_state, clients, userinfo_db, id_token_lifetime= int(settings.oidc.id_token_lifetime))

        with open(settings.oidc.rsa_public_key, 'r', encoding='utf-8') as rsa_pub_key:
            self.key = rsa_pub_key.read()

    def __getattr__(self, name: str) -> Any:
        if hasattr(self.provider, name):
            return getattr(self.provider, name)

        raise AttributeError(f"Attribute {name} not found")
