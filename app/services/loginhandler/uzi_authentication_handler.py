# pylint: disable=duplicate-code
import logging
import time
from typing import Any, Dict

from fastapi import Request

from pyop.message import AuthorizationRequest

from app.models.authorize_response import AuthorizeResponse
from app.services.encryption.jwt_service import JWTService
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
        jwt_service: JWTService,
        external_session_service: ExternalSessionService,
        clients: Dict[str, Any],
        session_jwt_issuer: str,
        session_jwt_audience: str,
    ):
        self._uzi_login_redirect_url = uzi_login_redirect_url
        self._response_factory = response_factory
        self._jwt_service = jwt_service
        self._external_session_service = external_session_service
        self._clients = clients
        self._session_jwt_issuer = session_jwt_issuer
        self._session_jwt_audience = session_jwt_audience

    def authentication_state(
        self, authorize_request: AuthorizeRequest
    ) -> Dict[str, Any]:
        client = self._clients[authorize_request.client_id]
        claims = {
            "iss": self._session_jwt_issuer,
            "aud": self._session_jwt_audience,
            "nbf": int(time.time()) - 10,
            "exp": int(time.time()) + 60,
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

        jwt = self._jwt_service.create_jwt(claims)
        uzi_response = self._external_session_service.create_session(
            jwt, claims["session_type"]
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
        claims = {
            "iss": self._session_jwt_issuer,
            "aud": self._session_jwt_audience,
            "exchange_token": exchange_token,
        }
        exchange_token_jwt = self._jwt_service.create_jwt(claims)
        external_session_status = self._external_session_service.get_session_status(
            exchange_token_jwt
        )

        return external_session_status
