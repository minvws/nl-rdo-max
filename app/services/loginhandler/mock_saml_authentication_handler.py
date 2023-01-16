from typing import Dict, Any

from fastapi import Request
from pyop.message import AuthorizationRequest
from starlette.responses import Response

from app.models.authorize_request import AuthorizeRequest
from app.services.loginhandler.saml_authentication_handler import (
    SamlAuthenticationHandler,
)


class MockSamlAuthenticationHandler(SamlAuthenticationHandler):
    def authorize_response(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        pyop_authentication_request: AuthorizationRequest,
        authentication_state: Dict[str, Any],
        randstate: str,
    ) -> Response:
        identity_provider = self._get_identity_provider(
            authentication_state["identity_provider_name"]
        )
        return self._saml_response_factory.create_saml_mock_response(
            identity_provider, authorize_request, randstate
        )
