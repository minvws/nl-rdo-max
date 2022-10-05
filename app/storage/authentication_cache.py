from app.storage.cache import Cache

from pyop.message import AuthorizationRequest
from app.models.authorize_request import AuthorizeRequest

from app.constants import AUTHENTICATION_REQUEST_PREFIX

class AuthenticationCache():
    def __init__(
        self,
        cache: Cache
    ):
        self._cache = cache

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
        }
        self._cache.set_complex_object(state_key, value)
        return rand_state
