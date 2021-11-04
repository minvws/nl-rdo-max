"""
Utilities creating strings to be returned to a user or endpoint.

Required:
    - settings.saml.authn_request_html_template
    - Template in location 'saml/templates/html/assertion_consumer_service.html'
"""

from typing import Text, List

from oic.oic.message import AuthorizationRequest as OICAuthRequest

from .oidc.authorize import validate_jwt_token

from .cache import RedisCache
from .models import AuthorizeRequest
from .exceptions import ExpiredResourceError

from . import constants


def create_redis_bsn_key(key: str, id_token: str, audience: List[Text]) -> str:
    """
    Method retrieving the redis_bsn_key used to retrieve the bsn from redis. This is the hash of the id_token that has
    been provided as a response to the accesstoken request.
    """
    jwt = validate_jwt_token(key, id_token, audience)
    return jwt["at_hash"]


def cache_auth_req(
    redis_cache: RedisCache,
    randstate: str,
    auth_req: OICAuthRequest,
    authorization_request: AuthorizeRequest,
    id_provider: str,
) -> None:
    """
    Method for assembling the data related to the auth request performed, including the code_challenge,
    code_challenge_method and the to be used identity provider. and storing it in the RedisStore under the
    constants.RedisKeys.AUTH_REQ enum.
    """
    value = {
        "auth_req": auth_req,
        "code_challenge": authorization_request.code_challenge,
        "code_challenge_method": authorization_request.code_challenge_method,
        "id_provider": id_provider,
    }

    redis_cache.hset(randstate, constants.RedisKeys.AUTH_REQ.value, value)


def cache_code_challenge(
    redis_cache: RedisCache, code: str, code_challenge: str, code_challenge_method: str
) -> None:
    """
    Method for assembling the data related to the upcoming accesstoken request, including the code, code_challenge
    and code_challenge_method. and storing it in the RedisStore under the constants.RedisKeys.CC_CM enum.
    """
    value = {
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }
    redis_cache.hset(code, constants.RedisKeys.CC_CM.value, value)


def cache_artifact(redis_cache: RedisCache, code: str, artifact: str, id_provider: str):
    """
    Method for assembling the data related to the upcoming accesstoken request, including the artifact and
    identity_provider that has been used to retrieve the artifact. These are stored in the RedisStore under the
    constants.RedisKeys.CC_CM enum.
    """
    value = {"artifact": artifact, "id_provider": id_provider}
    redis_cache.hset(code, constants.RedisKeys.ARTI.value, value)


def hget_from_redis(redis_cache: RedisCache, namespace, key):
    """
    Method to retrieve something from redis, and if no result is found, throw a resource has expired exception.
    """
    result = redis_cache.hget(namespace, key)
    if result is None:
        raise ExpiredResourceError("Resource is not available in our cache")
    return result
