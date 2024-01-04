import base64
import json
from typing import Any, Union, Dict, Optional

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

    def create_randstate(
        self,
        authorization_request: AuthorizationRequest,
        authorize_request: AuthorizeRequest,
    ) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(
                {
                    "state": self._cache.gen_token(),
                    "client_id": authorize_request.client_id,
                    "redirect_uri": authorization_request["redirect_uri"],
                }
            ).encode("utf-8")
        ).decode("utf-8")

    def cache_authentication_request_state(
        self,
        authorization_request: AuthorizationRequest,
        authorize_request: AuthorizeRequest,
        randstate: str,
        authentication_state: Dict[str, Any],
        login_option: str,
        session_id: str,
        req_acme_token: Optional[str],
    ) -> None:
        authentication_context = AuthenticationContext(
            authorization_request=authorization_request,
            authorization_by_proxy=authorize_request.authorization_by_proxy,
            authentication_method=login_option,
            authentication_state=authentication_state,
            session_id=session_id,
            req_acme_token=req_acme_token,
        )
        self.cache_authentication_context(randstate, authentication_context)

    def cache_authentication_context(
        self, randstate: str, authentication_context: AuthenticationContext
    ):
        state_key = f"{AUTHENTICATION_REQUEST_PREFIX}:{randstate}"
        self._cache.set_complex_object(state_key, authentication_context)

    def get_authentication_request_state(
        self, randstate: str
    ) -> Union[AuthenticationContext, None]:
        state_key = f"{AUTHENTICATION_REQUEST_PREFIX}:{randstate}"
        return self._cache.get_and_delete_complex_object(
            state_key, AuthenticationContext
        )

    def cache_acs_context(self, code: str, acs_context: AcsContext) -> None:
        acs_context_key = f"{ACS_CONTEXT_PREFIX}:{code}"
        self._cache.set_complex_object(acs_context_key, acs_context)

    def get_acs_context(self, code: str) -> Union[AcsContext, None]:
        return self._cache.get_and_delete_complex_object(
            f"{ACS_CONTEXT_PREFIX}:{code}", AcsContext
        )

    def cache_userinfo_context(
        self, userinfo_key: str, access_token: str, acs_context: AcsContext
    ):
        userinfo_context_serialized = (
            self._authentication_context_encryption_service.symm_encrypt(
                UserinfoContext(
                    client_id=acs_context.client_id,
                    authentication_method=acs_context.authentication_method,
                    access_token=access_token,
                    userinfo=acs_context.userinfo,
                )
                .json()
                .encode("utf-8")
            )
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
