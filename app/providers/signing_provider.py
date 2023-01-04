import logging

from fastapi import Request, Response
from pyop.provider import Provider as PyopProvider, extract_bearer_token_from_http_request  # type: ignore[attr-defined]

from app.storage.authentication_cache import AuthenticationCache

log = logging.getLogger(__package__)


class SigningProvider:
    def __init__(
            self,
            _authentication_cache: AuthenticationCache
    ):
        self._authentication_cache = _authentication_cache

    def fetch_signing_jwt(self, request: Request, validation_token: str):
        bearer_token = extract_bearer_token_from_http_request(
            authz_header=request.headers.get("Authorization")
        )

        # todo: id_token valid until same as redis cache ttl
        introspection = (
            self._pyop_provider.authz_state.introspect_access_token(  # type:ignore
                bearer_token
            )
        )
        userinfo_context = (
            self._authentication_cache.get_userinfo_context(bearer_token)
        )
        if not introspection["active"]:
            raise Exception("not authorized")
        return Response(
            headers={"Content-Type": "application/jwt"},
            content=userinfo_context.userinfo,
        )
