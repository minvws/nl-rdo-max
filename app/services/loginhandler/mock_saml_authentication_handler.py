from typing import Dict, Any

from fastapi import Request
from pyop.message import AuthorizationRequest
from starlette.responses import Response

from app.models.acs_context import AcsContext
from app.models.authorize_request import AuthorizeRequest
from app.models.saml.assertion_consumer_service_request import AssertionConsumerServiceRequest
from app.services.loginhandler.saml_authentication_handler import SamlAuthenticationHandler


class MockSamlAuthenticationHandler(SamlAuthenticationHandler):

    def authorize_response(
            self,
            request: Request,
            authorize_request: AuthorizeRequest,
            pyop_authentication_request: AuthorizationRequest,
            authorize_state: Dict[str, Any],
            randstate: str
    ) -> Response:
        identity_provider = self._get_identity_provider(authorize_state["identity_provider_name"])
        return self._saml_response_factory.create_saml_mock_response(identity_provider, authorize_request, randstate)

    def resolve_authentication_artifact(self, acs_context: AcsContext) -> Any:
        context: AssertionConsumerServiceRequest = acs_context.context # todo: Cleanup
        return self._userinfo_service.request_userinfo_for_artifact(acs_context)
