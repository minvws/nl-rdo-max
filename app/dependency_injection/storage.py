# pylint: disable=c-extension-no-member, too-few-public-methods

from dependency_injector import containers, providers

from app.storage.authentication_cache import AuthenticationCache
from app.storage.redis.redis_cache import RedisCache
from app.storage.redis.redis_client import create_redis_client
from app.storage.redis.redis_debugger import RedisGetDebuggerFactory
from app.storage.redis.redis_wrapper import RedisWrapper


class Storage(containers.DeclarativeContainer):
    config = providers.Configuration()

    encryption_services = providers.DependenciesContainer()

    redis_client = providers.Singleton(create_redis_client, config.redis)

    redis_get_debugger_factory = providers.Singleton(
        RedisGetDebuggerFactory,
        redis_client=redis_client,
        loglevel=config.app.loglevel.as_(str.upper),
        redis_object_ttl=config.redis.object_ttl.as_int(),
        redis_default_cache_namespace=config.redis.default_cache_namespace,
    )

    cache = providers.Singleton(
        RedisCache,
        default_cache_namespace=config.redis.default_cache_namespace,
        enable_debugger=config.redis.enable_debugger.as_(bool),
        expires_in_seconds=config.redis.object_ttl.as_int(),
        redis_client=redis_client,
        redis_get_debugger_factory=redis_get_debugger_factory,
    )

    authorization_code_db = providers.Singleton(
        RedisWrapper,
        redis_client=redis_client,
        collection=config.redis.code_namespace,
        ttl=config.redis.object_ttl.as_int(),
    )

    access_token_db = providers.Singleton(
        RedisWrapper,
        redis_client=redis_client,
        collection=config.redis.token_namespace,
        ttl=config.redis.object_ttl.as_int(),
    )

    refresh_token_db = providers.Singleton(
        RedisWrapper,
        redis_client=redis_client,
        collection=config.redis.refresh_token_namespace,
        ttl=config.redis.object_ttl.as_int(),
    )

    subject_identifier_db = providers.Singleton(
        RedisWrapper,
        redis_client=redis_client,
        collection=config.redis.subject_identifier_namespace,
        ttl=config.redis.object_ttl.as_int(),
    )

    authentication_cache = providers.Singleton(
        AuthenticationCache,
        cache=cache,
        authentication_context_encryption_service=encryption_services.user_authentication_encryption_service,
        app_mode=config.app.app_mode,
    )
