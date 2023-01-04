import logging

import requests

from app.misc.rate_limiter import RateLimiter
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
    ):
        self._saml_response_factory = saml_response_factory
        self._oidc_provider = oidc_provider
        self._saml_identity_provider_service = saml_identity_provider_service
        self._rate_limiter = rate_limiter
        self._userinfo_service = userinfo_service

    def handle_assertion_consumer_service(
            self, request: AssertionConsumerServiceRequest
    ):
        identity_provider_name = self._rate_limiter.get_identity_provider_name_based_on_request_limits()
        identity_provider = self._saml_identity_provider_service.get_identity_provider(identity_provider_name)
        authentication_context = self._oidc_provider.get_authentication_request_state(request.RelayState)
        url = identity_provider.idp_metadata.get_artifact_rs()["location"]
        resolve_artifact_req = identity_provider.create_artifactresolve_request(request.SAMLart)
        headers = {"SOAPAction": "resolve_artifact", "content-type": "text/xml"}
        response = requests.post(
            url,
            headers=headers,
            data=resolve_artifact_req.get_xml(xml_declaration=True),
            cert=(identity_provider.cert_path, identity_provider.key_path),
            verify=False  # fixme: Remove this
        )
        # todo: error handling, raise for status

        userinfo = self._userinfo_service.request_userinfo_for_artifact(
            authentication_context,
            response.text,
            identity_provider
        )
        response_url = self._oidc_provider.handle_external_authentication(authentication_context, userinfo)
        return self._saml_response_factory.create_saml_meta_redirect_response(
            response_url
        )
    #todo: !!
        # """
        # This callback function handles the redirects retrieved from the active IDP, once the resource owner
        # has logged into the active IDP, the IDP redirects the user to this endpoint with the provided artifact.
        # This artifact is stored, and the user is redirected to the configured redirect_uri. The retrieved artifact
        # is later used to verify the login, and retrieve the BSN.
        # """
        # authentication_request = self._authentication_cache.get_authentication_request_state(request.RelayState)
        # if authentication_request is None:
        #     raise UnauthorizedError("Not authorized")
        # auth_req = authentication_request.authorization_request
        # if not request.:
        #     log.error(
        #         "received no auth request for artifact %s.",
        #         request.hashed_saml_art(),
        #         exc_info=True,
        #     )
        #     return HTMLResponse(
        #         status_code=404, content="Session expired, user not authorized"
        #     )
        #
        # # TODO: Change this to client from clients.json, if possible
        # pyop_authorize_response = self._pyop_provider.authorize(  # type:ignore
        #     auth_req, "client"
        # )
        #
        # login_handler = self._authentication_handler_factory.create(authentication_request.authentication_method)
        # login_handler.resolve_authentication_artifact()
        # print()
        # raise SystemExit("stop")
        # acs_context = AcsContext(
        #     client_id=authentication_request.authorization_request["client_id"],
        #     authentication_method=authentication_request.authentication_method,
        #     authentication_state=authentication_request.authentication_state,
        #     context=request
        # )
        # self._authentication_cache.cache_acs_context(pyop_authorize_response["code"], acs_context)
        #
        # response_url = pyop_authorize_response.request(auth_req["redirect_uri"], False)
        #
        # return self._saml_response_factory.create_saml_meta_redirect_response(
        #     response_url
        # )

    # todo: Implement metadata request
    # pylint:disable= unused-argument
    def metadata(self, id_provider_name: str):
        """
        Endpoint retrieving metadata for the specified identity providers if configured properly.
        """
        return ""
