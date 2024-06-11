import logging
from typing import Any, Dict

from fastapi import Request

from pyop.message import AuthorizationRequest

from app.models.authorize_response import AuthorizeResponse
from app.services.external_session_service import ExternalSessionService

from app.models.authorize_request import AuthorizeRequest
from app.services.loginhandler.exchange_based_authentication_handler import (
    ExchangeBasedAuthenticationHandler,
)
from app.services.response_factory import ResponseFactory

logger = logging.getLogger(__name__)


class UziAuthenticationHandler(ExchangeBasedAuthenticationHandler):
    def __init__(
        self,
        uzi_login_redirect_url: str,
        response_factory: ResponseFactory,
        external_session_service: ExternalSessionService,
        clients: Dict[str, Any],
    ):
        self._uzi_login_redirect_url = uzi_login_redirect_url
        self._response_factory = response_factory
        self._external_session_service = external_session_service
        self._clients = clients

    def authentication_state(
        self, authorize_request: AuthorizeRequest
    ) -> Dict[str, Any]:
        client = self._clients[authorize_request.client_id]
        claims = {
            "disclosures": [{"disclose_type": "uziId"}, {"disclose_type": "roles"}],
            "session_type": "uzi_card",
            "login_title": client["name"],
        }
        disclose = [{"disclose_type": "uziId"}, {"disclose_type": "roles"}]

        if client["external_id"] == "*":
            # Request disclosure of entityName and ura
            disclose.append({"disclose_type": "entityName"})
            disclose.append({"disclose_type": "ura"})
        else:
            # Request disclosure of entityName and ura with specific values
            disclose.append(
                {"disclose_type": "entityName", "disclose_value": client["name"]}
            )
            disclose.append(
                {"disclose_type": "ura", "disclose_value": client["external_id"]}
            )

        uzi_response = self._external_session_service.create_session(
            claims, claims["session_type"]
        )

        return uzi_response

    def authorize_response(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        pyop_authentication_request: AuthorizationRequest,
        authentication_state: Dict[str, Any],
        randstate: str,
    ) -> AuthorizeResponse:
        return AuthorizeResponse(
            response=self._response_factory.create_redirect_response(
                redirect_url=f"{self._uzi_login_redirect_url}/{authentication_state['exchange_token']}?state={randstate}"
            )
        )

    def get_external_session_status(self, exchange_token: str) -> str:
        external_session_status = self._external_session_service.get_session_status(
            exchange_token
        )

        return external_session_status
