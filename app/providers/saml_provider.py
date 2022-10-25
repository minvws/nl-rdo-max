import logging

from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from pyop.provider import Provider as PyopProvider

from app.models.saml.assertion_consumer_service_request import AssertionConsumerServiceRequest
from app.services.saml.saml_response_factory import SAMLResponseFactory
from app.storage.authentication_cache import AuthenticationCache


log = logging.getLogger(__package__)


class SAMLProvider:

    def __init__(
            self,
            authentication_cache: AuthenticationCache,
            pyop_provider: PyopProvider,
            saml_response_factory: SAMLResponseFactory
    ):
        self._pyop_provider = pyop_provider
        self._authentication_cache = authentication_cache
        self._saml_response_factory = saml_response_factory

    def assertion_consumer_service(self, request: AssertionConsumerServiceRequest):
        """
        This callback function handles the redirects retrieved from the active IDP, once the resource owner
        has logged into the active IDP, the IDP redirects the user to this endpoint with the provided artifact.
        This artifact is stored, and the user is redirected to the configured redirect_uri. The retrieved artifact
        is later used to verify the login, and retrieve the BSN.
        """
        # Decode artifact
        # If mocking -> store
        authentication_request = self._authentication_cache.get_authentication_request_state(request.RelayState)
        auth_req = authentication_request["auth_req"]
        if not authentication_request:
            log.error("received no auth request for artifact %s.", request.hashed_saml_art(), exc_info=True)
            return HTMLResponse(status_code=404, content="Session expired, user not authorized")

        # TODO: Change this to client from clients.json, if possible
        pyop_authorize_response = self._pyop_provider.authorize(auth_req, "client")
        self._authentication_cache.cache_acs_context(
            pyop_authorize_response,
            authentication_request,
            request
        )

        response_url = pyop_authorize_response.request(auth_req["redirect_uri"], False)

        return self._saml_response_factory.create_saml_meta_redirect_response(response_url)

    # todo: Implement metadata request
    def metadata(self, id_provider_name: str):
        """
        Endpoint retrieving metadata for the specified identity providers if configured properly.
        """
        return ""
