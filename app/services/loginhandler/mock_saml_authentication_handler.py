from typing import Dict, Any

from fastapi import Request
from pyop.message import AuthorizationRequest

from app.models.authorize_request import AuthorizeRequest
from app.models.authorize_response import AuthorizeResponse
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
    ) -> AuthorizeResponse:
        return AuthorizeResponse(
            response=self._saml_response_factory.create_saml_mock_response(
                authorize_request, randstate
            )
        )
