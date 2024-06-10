import logging
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


class OidcAuthenticationHandler(ExchangeBasedAuthenticationHandler):
    def __init__(
        self,
        response_factory: ResponseFactory,
        oidc_login_redirect_url: str,
        session_jwt_issuer: str,
        session_jwt_audience: str,
        clients: Dict[str, Any],
        jwt_service: JWTService,
        external_session_service: ExternalSessionService,
    ):
        self._response_factory = response_factory
        self._clients = clients
        self._session_jwt_issuer = session_jwt_issuer
        self._session_jwt_audience = session_jwt_audience
        self._oidc_login_redirect_url = oidc_login_redirect_url
        self._jwt_service = jwt_service
        self._external_session_service = external_session_service

    def authentication_state(
        self, authorize_request: AuthorizeRequest
    ) -> Dict[str, Any]:
        client = self._clients[authorize_request.client_id]
        oidc_provider_name = authorize_request.login_hint
        claims = {
            "iss": self._session_jwt_issuer,
            "aud": self._session_jwt_audience,
            "session_type": "oidc",
            "login_title": client["name"],
            "oidc_provider_name": oidc_provider_name,
        }
        jwt = self._jwt_service.create_jwt(claims)
        uzi_response = self._external_session_service.get_exchange_token(jwt)
        return uzi_response

    def authorize_response(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        pyop_authentication_request: AuthorizationRequest,
        authentication_state: Dict[str, Any],
        randstate: str,
    ) -> AuthorizeResponse:
        exchange_token = authentication_state["exchange_token"]
        return AuthorizeResponse(
            response=self._response_factory.create_redirect_response(
                redirect_url=f"{self._oidc_login_redirect_url}/{exchange_token}?state={randstate}"
            )
        )

    def get_external_session_status(self, exchange_token: str):
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
