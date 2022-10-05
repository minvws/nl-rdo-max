from fastapi import Request

from app.services.authentication_cache_service import AuthenticationCacheService


class SAMLProvider():

    def __init__(
        self,
        authentication_cache_service: AuthenticationCacheService
    ):
        self._authentication_cache_service = authentication_cache_service

    def assertion_consumer_service(self, request: Request):
        """
        This callback function handles the redirects retrieved from the active IDP, once the resource owner
        has logged into the active IDP, the IDP redirects the user to this endpoint with the provided artifact.
        This artifact is stored, and the user is redirected to the configured redirect_uri. The retrieved artifact
        is later used to verify the login, and retrieve the BSN.
        """
        # user should be authorized!

        return ""

    def metadata(self, id_provider_name: str):
        """
        Endpoint retrieving metadata for the specified identity providers if configured properly.
        """
        return ""
