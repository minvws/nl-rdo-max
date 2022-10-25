import json
from typing import Any, Union

from app.models.saml.assertion_consumer_service_request import AssertionConsumerServiceRequest
from app.services.encryption.sym_encryption_service import SymEncryptionService
from app.storage.cache import Cache

from pyop.message import AuthorizationRequest
from app.models.authorize_request import AuthorizeRequest

from app.constants import AUTHENTICATION_REQUEST_PREFIX, ACS_CONTEXT_PREFIX, ID_TOKEN_PREFIX
from jwcrypto.jwt import JWT


class AuthenticationCache:
    def __init__(
            self,
            cache: Cache,
            authentication_context_encryption_service: SymEncryptionService,
            app_mode: Union[str, None]
    ):
        self._cache = cache
        self._authentication_context_encryption_service = authentication_context_encryption_service
        self._app_mode = app_mode

    def create_authentication_request_state(
        self,
        pyop_authentication_request: AuthorizationRequest,
        authorize_request: AuthorizeRequest,
        identity_provider_name: str
    ) -> str:
        rand_state = self._cache.gen_token()
        state_key = f"{AUTHENTICATION_REQUEST_PREFIX}:{rand_state}"
        value = {
            "auth_req": pyop_authentication_request,
            "code_challenge": authorize_request.code_challenge,
            "code_challenge_method": authorize_request.code_challenge_method,
            "authorization_by_proxy": authorize_request.authorization_by_proxy,
            "id_provider": identity_provider_name,
            "client_id": authorize_request.client_id
        }
        self._cache.set_complex_object(state_key, value)
        return rand_state

    def get_authentication_request_state(
        self,
        rand_state: str
    ) -> Any:
        state_key = f"{AUTHENTICATION_REQUEST_PREFIX}:{rand_state}"
        return self._cache.get_complex_object(state_key)

    def cache_acs_context(
            self,
            pyop_authorize_response,
            pyop_authorize_request,
            acs_request: AssertionConsumerServiceRequest
    ) -> None:
        self._cache.set_complex_object(
            f"{ACS_CONTEXT_PREFIX}:{pyop_authorize_response['code']}",
            {
                "id_provider": pyop_authorize_request["id_provider"],
                "authorization_by_proxy": pyop_authorize_request["authorization_by_proxy"],
                "code_challenge": pyop_authorize_request["code_challenge"],
                "code_challenge_method": pyop_authorize_request["code_challenge_method"],
                "artifact": acs_request.SAMLart,
                "mocking": acs_request.mocking,
                "client_id": pyop_authorize_request["client_id"]
            })

    def get_acs_context(
            self,
            code: str
    ):
        return self._cache.get_complex_object(f"{ACS_CONTEXT_PREFIX}:{code}")

    def cache_authentication_context(
            self,
            pyop_token_response: dict,
            external_user_authentication_context: str
    ):
        user_authentication_context = {
            "id_token": pyop_token_response["id_token"],
            "external_user_authentication_context":
                self._authentication_context_encryption_service.symm_encrypt(
                    external_user_authentication_context.encode("utf-8"))
        }
        if self._app_mode == "legacy":
            user_authentication_context["access_token"] = pyop_token_response["access_token"]
            id_jwt = JWT.from_jose_token(pyop_token_response['id_token'])
            at_hash_key = json.loads(id_jwt.token.objects['payload'].decode('utf-8'))['at_hash']
            return self._cache.set_complex_object(
                f"{ID_TOKEN_PREFIX}:{at_hash_key}",
                user_authentication_context
            )
        return self._cache.set_complex_object(
            f"{ID_TOKEN_PREFIX}:{pyop_token_response['access_token']}",
            user_authentication_context
        )

    def get_authentication_context(
            self,
            access_token: str
    ):
        if self._app_mode == "legacy":
            id_jwt = JWT.from_jose_token(access_token)
            at_hash_key = json.loads(id_jwt.token.objects['payload'].decode('utf-8'))['at_hash']
            authentication_context = self._cache.get_complex_object(
                f"{ID_TOKEN_PREFIX}:{at_hash_key}"
            )
        else:
            authentication_context = self._cache.get_complex_object(
                f"{ID_TOKEN_PREFIX}:{access_token}"
            )
        authentication_context["external_user_authentication_context"] = \
            self._authentication_context_encryption_service.symm_decrypt(
                authentication_context["external_user_authentication_context"]).decode("utf-8")
        return authentication_context
