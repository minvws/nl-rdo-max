import json
import logging
from typing import Any, Dict

import requests
from fastapi import Request
from pyop.message import AuthorizationRequest
from starlette.responses import Response

from app.exceptions.max_exceptions import (
    UnauthorizedError,
)
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
    ):
        self._jwe_service_provider = jwe_service_provider
        self._response_factory = response_factory
        self._create_irma_session_url = create_irma_session_url
        self._irma_login_redirect_url = irma_login_redirect_url
        self._clients = clients

    def authentication_state(
        self, authorize_request: AuthorizeRequest
    ) -> Dict[str, Any]:
        client = self._clients[authorize_request.client_id]
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
        irma_response = requests.post(
            f"{self._create_irma_session_url}",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"requested_disclosures": disclose}),
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
