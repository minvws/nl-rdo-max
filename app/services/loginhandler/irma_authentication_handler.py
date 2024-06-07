import logging
import time
from typing import Any, Dict

import requests
from cryptography.hazmat.primitives import hashes
from fastapi import Request
from jwcrypto.jwt import JWT
from pyop.message import AuthorizationRequest
from requests import Response

from app.exceptions.max_exceptions import (
    UnauthorizedError,
)
from app.models.authorize_request import AuthorizeRequest
from app.models.authorize_response import AuthorizeResponse

from app.services.loginhandler.common_fields import CommonFields
from app.services.loginhandler.exchange_based_authentication_handler import (
    ExchangeBasedAuthenticationHandler,
)

logger = logging.getLogger(__name__)


# pylint: disable=too-many-arguments
class IrmaAuthenticationHandler(CommonFields, ExchangeBasedAuthenticationHandler):
    def __init__(self, irma_login_redirect_url: str, **kwargs):
        super().__init__(**kwargs)
        self._irma_login_redirect_url = irma_login_redirect_url

    def authentication_state(
        self, authorize_request: AuthorizeRequest
    ) -> Dict[str, Any]:
        client = self._clients[authorize_request.client_id]
        header = {
            "alg": "RS256",
            "x5t": self._private_sign_jwk_key.thumbprint(hashes.SHA256()),
            "kid": self._public_sign_jwk_key.kid,
        }
        claims = {
            "iss": self._session_jwt_issuer,
            "aud": self._session_jwt_audience,
            "nbf": int(time.time()) - 10,
            "exp": int(time.time()) + 60,
            "session_type": "irma",
            "login_title": client["name"],
        }
        jwt = JWT(header=header, claims=claims)
        jwt.make_signed_token(self._private_sign_jwk_key)

        jwt_s = jwt.serialize()
        irma_response = requests.post(
            f"{self._session_url}",
            headers={"Content-Type": "text/plain"},
            data=jwt_s,
            timeout=self._external_http_requests_timeout_seconds,
        )
        if irma_response.status_code >= 400:
            raise UnauthorizedError(
                log_message="Error while fetching IrmaResponse, Irma server returned: "
                f"{irma_response.status_code}, {irma_response.text}",
                error_description="Unable to create IRMA session",
            )
        return {"exchange_token": irma_response.json()}

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
                redirect_url=f"{self._irma_login_redirect_url}/{authentication_state['exchange_token']}?state={randstate}"
            )
        )

    def get_external_session_status(self, exchange_token: str) -> Response:
        exchange_token_jwt = JWT(
            header={
                "alg": "RS256",
                "x5t": self._private_sign_jwk_key.thumbprint(hashes.SHA256()),
                "kid": self._public_sign_jwk_key.kid,
            },
            claims={
                "iss": self._session_jwt_issuer,
                "aud": self._session_jwt_audience,
                "nbf": int(time.time()) - 10,
                "exp": int(time.time()) + 60,
                "exchange_token": exchange_token,
            },
        )
        exchange_token_jwt.make_signed_token(self._private_sign_jwk_key)
        serialized_jwt = exchange_token_jwt.serialize()

        external_session_status = requests.get(
            f"{self._session_url}/status",
            headers={
                "Content-Type": "text/plain",
                "Authorization": f"Bearer {serialized_jwt}",
            },
            timeout=self._external_http_requests_timeout_seconds,
        )
        return external_session_status
