# pylint: disable=duplicate-code
import logging
import time
from typing import Any, Dict, List

import requests
from cryptography.hazmat.primitives import hashes
from fastapi import Request
from jwcrypto.jwt import JWT
from pyop.message import AuthorizationRequest

from app.models.authorize_response import AuthorizeResponse
from app.services.loginhandler.common_fields import CommonFields
from app.exceptions.max_exceptions import (
    UnauthorizedError,
)
from app.models.authorize_request import AuthorizeRequest
from app.services.loginhandler.authentication_handler import AuthenticationHandler

logger = logging.getLogger(__name__)


# pylint: disable=too-many-arguments
class OidcAuthenticationHandler(CommonFields, AuthenticationHandler):
    def __init__(
        self,
        oidc_login_redirect_url: str,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._oidc_login_redirect_url = oidc_login_redirect_url

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
            "session_type": "oidc",
            "login_title": client["name"],
        }
        jwt = JWT(header=header, claims=claims)
        jwt.make_signed_token(self._private_sign_jwk_key)
        disclose = [{"disclose_type": "uziId"}, {"disclose_type": "roles"}]
        if "disclosure_clients" in client:
            disclose.append({"disclose_type": "entityName"})
            disclose.append({"disclose_type": "ura"})
        else:
            disclose.append(
                {"disclose_type": "entityName", "disclose_value": client["name"]}
            )
            disclose.append(
                {"disclose_type": "ura", "disclose_value": client["external_id"]}
            )
        jwt_s = jwt.serialize()
        uzi_response = requests.post(
            f"{self._session_url}",
            headers={"Content-Type": "text/plain"},
            data=jwt_s,
            timeout=self._external_http_requests_timeout_seconds,
        )
        if uzi_response.status_code >= 400:
            raise UnauthorizedError(
                log_message="Error while fetching UziResponse, Uzi server returned: "
                f"{uzi_response.status_code}, {uzi_response.text}",
                error_description="Unable to create UZI session",
            )
        return {"exchange_token": uzi_response.json()}

    def authorize_response(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        pyop_authentication_request: AuthorizationRequest,
        authentication_state: Dict[str, Any],
        randstate: str,
    ) -> AuthorizeResponse:
        exchange_token = authentication_state["exchange_token"]
        provider_name = pyop_authentication_request.get("login_hint")
        return AuthorizeResponse(
            response=self._response_factory.create_redirect_response(
                redirect_url=f"{self._oidc_login_redirect_url}/{provider_name}?exchange_token={exchange_token}&state={randstate}"
            )
        )
