from typing import Any, Dict

import requests
from fastapi import Request
from pyop.message import AuthorizationRequest
from starlette.responses import Response

from app.misc.rate_limiter import RateLimiter
from app.models.acs_context import AcsContext
from app.models.authorize_request import AuthorizeRequest
from app.services.loginhandler.authentication_handler import AuthenticationHandler
from app.services.saml.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.userinfo.userinfo_service import UserinfoService
from app.storage.authentication_cache import AuthenticationCache


class SamlAuthenticationHandler(AuthenticationHandler):
    def __init__(
            self,
            rate_limiter: RateLimiter,
            saml_identity_provider_service: SamlIdentityProviderService,
            authentication_cache: AuthenticationCache,
            saml_response_factory: SamlResponseFactory,
            userinfo_service: UserinfoService
    ):
        self._rate_limiter = rate_limiter
        self._saml_identity_provider_service = saml_identity_provider_service
        self._authentication_cache = authentication_cache
        self._saml_response_factory = saml_response_factory
        self._userinfo_service = userinfo_service

    def _get_identity_provider(self, identity_provider_name: str):
        return self._saml_identity_provider_service.get_identity_provider(identity_provider_name)

    def authentication_state(self, authorize_request: AuthorizeRequest) -> Dict[str, Any]:
        return {
            "identity_provider_name": self._rate_limiter.get_identity_provider_name_based_on_request_limits()
        }

    def resolve_authentication_artifact(self, acs_context: AcsContext) -> Any:
        identity_provider = self._saml_identity_provider_service.get_identity_provider(
            acs_context.authentication_state["identity_provider_name"]
        )
        url = identity_provider.idp_metadata.get_artifact_rs()["location"]
        resolve_artifact_req = identity_provider.create_artifactresolve_request(acs_context.context.SAMLart)
        headers = {"SOAPAction": "resolve_artifact", "content-type": "text/xml"}
        response = requests.post(
            url,
            headers=headers,
            data=resolve_artifact_req.get_xml(xml_declaration=True),
            cert=(identity_provider.cert_path, identity_provider.key_path),
            verify=False  # fixme: Remove this
        )
        # todo: error handling, raise for status
        return self._userinfo_service.request_userinfo_for_artifact(acs_context, response.text, identity_provider)

    def authorize_response(
            self,
            request: Request,
            authorize_request: AuthorizeRequest,
            pyop_authentication_request: AuthorizationRequest,
            authentication_state: Dict[str, Any],
            randstate: str
    ) -> Response:
        id_provider = self._saml_identity_provider_service.get_identity_provider(
            authentication_state["identity_provider_name"]
        )
        return self._saml_response_factory.create_saml_response(
            id_provider, authorize_request, randstate
        )
