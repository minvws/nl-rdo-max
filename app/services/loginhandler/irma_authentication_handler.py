import logging
import time
from typing import Any, Dict

import requests
from cryptography.hazmat.primitives import hashes
from fastapi import Request
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from pyop.message import AuthorizationRequest
from starlette.responses import Response

from app.exceptions.max_exceptions import (
    UnauthorizedError,
)
from app.misc.utils import file_content_raise_if_none
from app.models.authorize_request import AuthorizeRequest

# todo this to constant
from app.services.encryption.jwe_service_provider import JweServiceProvider
from app.services.loginhandler.authentication_handler import AuthenticationHandler
from app.services.response_factory import ResponseFactory

logger = logging.getLogger(__name__)


class IrmaAuthenticationHandler(AuthenticationHandler):
    def __init__(
        self,
        jwe_service_provider: JweServiceProvider,
        response_factory: ResponseFactory,
        create_irma_session_url: str,
        irma_login_redirect_url: str,
        clients: Dict[str, Any],
        session_jwt_issuer: str,
        session_jwt_audience: str,
        jwt_sign_priv_key_path: str,
        jwt_sign_crt_path: str,
    ):
        self._jwe_service_provider = jwe_service_provider
        self._response_factory = response_factory
        self._create_irma_session_url = create_irma_session_url
        self._irma_login_redirect_url = irma_login_redirect_url
        self._clients = clients
        self._session_jwt_issuer = session_jwt_issuer
        self._session_jwt_audience = session_jwt_audience
        jwt_sign_priv_key = file_content_raise_if_none(jwt_sign_priv_key_path)
        jwt_sign_crt = file_content_raise_if_none(jwt_sign_crt_path)
        self._private_sign_jwk_key = JWK.from_pem(jwt_sign_priv_key.encode("utf-8"))
        self._public_sign_jwk_key = JWK.from_pem(jwt_sign_crt.encode("utf-8"))

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
            "disclosures": [{"disclose_type": "uziId"}, {"disclose_type": "roles"}],
            "session_type": "irma",
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
        irma_response = requests.post(
            f"{self._create_irma_session_url}",
            headers={"Content-Type": "text/plain"},
            data=jwt_s,
            timeout=60,
        )
        if irma_response.status_code >= 400:
            logger.error(
                "Error while fetching IrmaResponse, Irma server returned: %s, %s",
                irma_response.status_code,
                irma_response.text,
            )
            raise UnauthorizedError(error_description="Unable to create IRMA session")
        return {"exchange_token": irma_response.json()}

    def authorize_response(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        pyop_authentication_request: AuthorizationRequest,
        authentication_state: Dict[str, Any],
        randstate: str,
    ) -> Response:
        return self._response_factory.create_redirect_response(
            redirect_url=f"{self._irma_login_redirect_url}/{authentication_state['exchange_token']}?state={randstate}"
        )
