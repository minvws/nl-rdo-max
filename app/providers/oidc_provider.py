import base64
import json
from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

from pyop.provider import Provider as PyopProvider

from app.exceptions.max_exceptions import AuthorizationByProxyDisabled
from app.models.authorize_request import AuthorizeRequest
from app.exceptions.oidc_exceptions import InvalidClientException, InvalidRedirectUriException
from app.models.login_digid_request import LoginDigiDRequest
from app.models.saml.exceptions import ScopingAttributesNotAllowed
from app.storage.authentication_cache import AuthenticationCache
from app.misc.rate_limiter import RateLimiter
from app.services.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml_response_factory import SAMLResponseFactory


class OIDCProvider():
    def __init__(
            self,
            pyop_provider: PyopProvider,
            authentication_cache: AuthenticationCache,
            rate_limiter: RateLimiter,
            clients: dict,
            saml_identity_provider_service: SamlIdentityProviderService,
            mock_digid: bool,
            saml_response_factory: SAMLResponseFactory
    ):
        self._pyop_provider = pyop_provider
        self._authentication_cache = authentication_cache
        self._rate_limiter = rate_limiter
        self._clients = clients
        self._saml_identity_provider_service = saml_identity_provider_service
        self._mock_digid = mock_digid
        self._saml_response_factory = saml_response_factory

    def well_known(self):
        return JSONResponse(
            content=jsonable_encoder(self._pyop_provider.provider_configuration.to_dict())
        )

    def authorize(self, authorize_request: AuthorizeRequest, request: Request):
        self._validate_authorize_request(authorize_request)
        self._rate_limiter.validate_outage()

        pyop_authentication_request = self._pyop_provider.parse_authentication_request(
            urlencode(authorize_request.dict()), request.headers
        )

        identity_provider_name = self._rate_limiter.get_identity_provider_name_and_validate_request(
            request.client.host
        )

        saml_identity_provider = self._saml_identity_provider_service.get_identity_provider(identity_provider_name)

        randstate = self._authentication_cache.create_authentication_request_state(
            pyop_authentication_request,
            authorize_request,
            identity_provider_name
        )

        login_digid_request = LoginDigiDRequest(state=randstate, authorize_request=authorize_request)

        return self._saml_response_factory.create_saml_response(
            self._mock_digid,
            saml_identity_provider,
            login_digid_request,
            randstate
        )

    def _validate_authorize_request(
            self,
            authorize_request: AuthorizeRequest
    ):
        """
        Validate the authorization request. If client_id or redirect_uri is invalid, we cannot redirect the
        user. Instead, return a 400 should be returned.
        """
        if authorize_request.client_id not in self._clients:
            raise InvalidClientException()

        if authorize_request.redirect_uri not in self._clients[authorize_request.client_id].get(
                "redirect_uris", []
        ):
            raise InvalidRedirectUriException()
