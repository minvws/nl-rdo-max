import logging

import requests

from app.misc.rate_limiter import RateLimiter
from app.models.saml.artifact_response_mock import ArtifactResponseMock
from app.models.saml.assertion_consumer_service_request import (
    AssertionConsumerServiceRequest,
)
from app.providers.oidc_provider import OIDCProvider
from app.services.saml.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.userinfo.userinfo_service import UserinfoService

log = logging.getLogger(__package__)


class SAMLProvider:
    def __init__(
            self,
            saml_response_factory: SamlResponseFactory,
            oidc_provider: OIDCProvider,
            saml_identity_provider_service: SamlIdentityProviderService,
            rate_limiter: RateLimiter,
            userinfo_service: UserinfoService,
            environment: str
    ):
        self._saml_response_factory = saml_response_factory
        self._oidc_provider = oidc_provider
        self._saml_identity_provider_service = saml_identity_provider_service
        self._rate_limiter = rate_limiter
        self._userinfo_service = userinfo_service
        self._environment = environment

    def handle_assertion_consumer_service(
            self, request: AssertionConsumerServiceRequest
    ):
        authentication_context = self._oidc_provider.get_authentication_request_state(request.RelayState)
        identity_provider = self._saml_identity_provider_service.get_identity_provider(authentication_context.authentication_state["identity_provider_name"])

        if not self._environment.startswith("prod") and authentication_context.authentication_method == "digid_mock":
            artifact_response = ArtifactResponseMock(request.SAMLart)
        else:
            artifact_response = identity_provider.resolve_artifact(request.SAMLart)

        userinfo = self._userinfo_service.request_userinfo_for_artifact(
            authentication_context,
            artifact_response,
            identity_provider
        )
        response_url = self._oidc_provider.handle_external_authentication(authentication_context, userinfo)
        return self._saml_response_factory.create_saml_meta_redirect_response(
            response_url
        )


    # todo: Implement metadata request
    # pylint:disable= unused-argument
    def metadata(self, id_provider_name: str):
        """
        Endpoint retrieving metadata for the specified identity providers if configured properly.
        """
        return ""
