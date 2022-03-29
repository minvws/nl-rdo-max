import warnings
from typing import Any

from pyop.authz_state import AuthorizationState
from pyop.provider import Provider as PyopProvider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

from .storage import RedisWrapper

# pylint: disable=too-few-public-methods
class Provider:
    """OIDC provider configuration. Allowing to handle authorize requests and
    supply JWT tokens.
    """

    @property
    def redis_cache(self):
        warnings.warn("This attribute should not be accessed.")
        return self._redis_cache

    @classmethod
    def fromsettings(cls, settings, storage_factory, redis_cache):
        return cls(
            issuer=settings.OIDC_ISSUER,
            authentication_endpoint=settings.OAUTH2_AUTHORIZATION_ENDPOINT,
            token_endpoint=settings.OAUTH2_TOKEN_ENDPOINT,
            jwks_uri=settings.JWKS_ENDPOINT,
            signing_key=settings.SIGNING_KEY,
            public_key=settings.OIDC_PUBLIC_KEY,
            clients=settings.OIDC_CLIENTS,
            id_token_lifetime=settings.TRANSIENT_OBJECT_TTL,
            subject_id_hash_salt=settings.SUBJECT_ID_HASH_SALT,
            authorization_code_db=storage_factory(
                collection=settings.REDIS_CODE_NS,
                ttl=settings.TRANSIENT_OBJECT_TTL,
            ),
            access_token_db=storage_factory(
                collection=settings.REDIS_TOKEN_NS, ttl=settings.TRANSIENT_OBJECT_TTL
            ),
            refresh_token_db=storage_factory(
                collection=settings.REDIS_REFRESH_TOKEN_NS,
                ttl=settings.TRANSIENT_OBJECT_TTL,
            ),
            subject_identifier_db=storage_factory(
                collection=settings.REDIS_SUBJECT_ID_NS,
                ttl=settings.TRANSIENT_OBJECT_TTL,
            ),
            redis_cache=redis_cache,
        )

    def __init__(  # pylint: disable=R0913
        self,
        issuer: str,
        authentication_endpoint: str,
        token_endpoint: str,
        jwks_uri: str,
        signing_key: bytes,
        public_key: str,
        clients: dict,
        id_token_lifetime: int,
        subject_id_hash_salt: str,
        authorization_code_db: RedisWrapper,
        access_token_db: RedisWrapper,
        refresh_token_db: RedisWrapper,
        subject_identifier_db: RedisWrapper,
        redis_cache,
    ) -> None:
        configuration_information = {
            "issuer": issuer,
            "authorization_endpoint": issuer + authentication_endpoint,
            "jwks_uri": issuer + jwks_uri,
            "token_endpoint": issuer + token_endpoint,
            "scopes_supported": ["openid"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["pairwise"],
            "token_endpoint_auth_methods_supported": ["none"],
            "claims_parameter_supported": True,
        }

        userinfo_db = Userinfo({"test_client": {"test": "test_client"}})
        authz_state = AuthorizationState(
            HashBasedSubjectIdentifierFactory(subject_id_hash_salt),
            authorization_code_db=authorization_code_db,
            access_token_db=access_token_db,
            refresh_token_db=refresh_token_db,
            subject_identifier_db=subject_identifier_db,
        )
        self.provider = PyopProvider(
            signing_key,
            configuration_information,  # type: ignore
            authz_state,
            clients,
            userinfo_db,
            id_token_lifetime=id_token_lifetime,
        )
        self.key = public_key
        self._redis_cache = redis_cache

    def __getattr__(self, name: str) -> Any:
        if hasattr(self.provider, name):
            return getattr(self.provider, name)

        raise AttributeError(f"Attribute {name} not found")
