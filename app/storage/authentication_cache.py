import base64
import json
from typing import Any, Union, Dict

from pyop.message import AuthorizationRequest

from app.constants import (
    AUTHENTICATION_REQUEST_PREFIX,
    ACS_CONTEXT_PREFIX,
    ID_TOKEN_PREFIX,
)
from app.models.acs_context import AcsContext
from app.models.authentication_context import AuthenticationContext
from app.models.authentication_request_context import UserinfoContext
from app.models.authorize_request import AuthorizeRequest
from app.services.encryption.sym_encryption_service import SymEncryptionService
from app.storage.cache import Cache


class AuthenticationCache:
    def __init__(
            self,
            cache: Cache,
            authentication_context_encryption_service: SymEncryptionService,
            app_mode: Union[str, None],
    ):
        self._cache = cache
        self._authentication_context_encryption_service = (
            authentication_context_encryption_service
        )
        self._app_mode = app_mode

    def create_authentication_request_state(
            self,
            authorization_request: AuthorizationRequest,
            authorize_request: AuthorizeRequest,
            authentication_state: Dict[str, Any],
    ) -> str:
        rand_state = base64.b64encode(
            json.dumps(
                {
                    "state": self._cache.gen_token(),
                    "client_id": authorize_request.client_id
                }).encode("utf-8")
        ).decode("utf-8")
        state_key = f"{AUTHENTICATION_REQUEST_PREFIX}:{rand_state}"
        authentication_context = AuthenticationContext(
            authorization_request=authorization_request,
            authorization_by_proxy=authorize_request.authorization_by_proxy,
            authentication_method=authorize_request.login_hints[0],
            authentication_state=authentication_state
        )
        self._cache.set_complex_object(state_key, authentication_context)
        return rand_state

    def get_authentication_request_state(self, rand_state: str) -> Union[AuthenticationContext, None]:
        state_key = f"{AUTHENTICATION_REQUEST_PREFIX}:{rand_state}"
        return self._cache.get_and_delete_complex_object(state_key)

    def cache_acs_context(
            self,
            code: str,
            acs_context: AcsContext
    ) -> None:
        acs_context_key = f"{ACS_CONTEXT_PREFIX}:{code}"
        self._cache.set_complex_object(acs_context_key, acs_context)

    def get_acs_context(self, code: str) -> Union[AcsContext, None]:
        return self._cache.get_and_delete_complex_object(f"{ACS_CONTEXT_PREFIX}:{code}")

    def cache_userinfo_context(
            self, userinfo_key: str, access_token: str, acs_context: AcsContext
    ):
        userinfo_context_serialized = self._authentication_context_encryption_service.symm_encrypt(
            UserinfoContext(
                client_id=acs_context.client_id,
                authentication_method=acs_context.authentication_method,
                access_token=access_token,
                userinfo=acs_context.userinfo
            ).json().encode("utf-8")
        )
        return self._cache.set(
            f"{ID_TOKEN_PREFIX}:{userinfo_key}",
            userinfo_context_serialized,
        )

    def get_userinfo_context(self, access_token: str) -> Union[UserinfoContext, None]:
        value = self._cache.get(f"{ID_TOKEN_PREFIX}:{access_token}")
        if value is not None:
            return UserinfoContext(
                **json.loads(
                    self._authentication_context_encryption_service.symm_decrypt(
                        value
                    ).decode("utf-8")
                )
            )
        return None
