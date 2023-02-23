import json
import logging
from app.exceptions.max_exceptions import UnauthorizedError

from starlette.responses import JSONResponse

from app.storage.authentication_cache import AuthenticationCache
from fastapi import Response
import requests
from app.services.userinfo.userinfo_service import UserinfoService
from app.providers.oidc_provider import OIDCProvider
from app.services.response_factory import ResponseFactory

logger = logging.getLogger(__name__)


class IRMAProvider:
    def __init__(
        self,
        authentication_cache: AuthenticationCache,
        irma_internal_server_url: str,
        userinfo_service: UserinfoService,
        oidc_provider: OIDCProvider,
        response_factory: ResponseFactory,
    ):
        self._authentication_cache = authentication_cache
        self._irma_internal_server_url = irma_internal_server_url
        self._userinfo_service = userinfo_service
        self._oidc_provider = oidc_provider
        self._response_factory = response_factory

    def irma_session(self, state: str) -> Response:
        authentication_request_state = (
            self._authentication_cache.get_authentication_request_state(state)
        )
        irma_response = requests.post(
            f"{self._irma_internal_server_url}/session",
            headers={"Content-Type": "application/json"},
            data=json.dumps(
                authentication_request_state.authentication_state["irma_context"]
            ),
        )
        if irma_response.status_code < 400:
            irma_response_obj = irma_response.json()
            authentication_request_state.authentication_state[
                "token"
            ] = irma_response_obj["token"]
            self._authentication_cache.cache_authentication_context(
                state,
                authentication_request_state,
            )
            return JSONResponse(content={"sessionPtr": irma_response_obj["sessionPtr"]})
        else:
            logger.error(
                f"Received status {irma_response.status_code} from IRMA server with content: {irma_response.text}"
            )

    def handle_irma_result(self, state: str):
        authentication_request_state = (
            self._authentication_cache.get_authentication_request_state(state)
        )
        if not authentication_request_state:
            raise UnauthorizedError(error_description="Session expired")
        irma_response = requests.get(
            f"{self._irma_internal_server_url}"
            + f"/session/{authentication_request_state.authentication_state['token']}/result",
        )
        if irma_response.status_code < 400:
            irma_response_obj = irma_response.json()
            authentication_context = (
                self._oidc_provider.get_authentication_request_state(state)
            )
            authentication_request_state.authentication_state[
                "token"
            ] = irma_response_obj["token"]
            print(self._userinfo_service)
            userinfo = self._userinfo_service.request_userinfo_for_irma_response(
                authentication_context, irma_response_obj
            )
            response_url = self._oidc_provider.handle_external_authentication(
                authentication_context, userinfo
            )
            return self._response_factory.create_saml_meta_redirect_response(
                response_url
            )
        else:
            logger.error(
                f"Received status {irma_response.status_code} from IRMA server with content: {irma_response.text}"
            )
