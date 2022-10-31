from urllib.parse import urlencode

from fastapi import Request, HTTPException, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pyop.provider import Provider as PyopProvider, extract_bearer_token_from_http_request  # type: ignore[attr-defined]
from starlette.datastructures import Headers

from app.exceptions.max_exceptions import ServerErrorException
from app.exceptions.oidc_exceptions import (
    InvalidClientException,
    InvalidRedirectUriException,
)
from app.misc.rate_limiter import RateLimiter
from app.models.authorize_request import AuthorizeRequest
from app.models.login_digid_request import LoginDigiDRequest
from app.models.token_request import TokenRequest
from app.services.saml.artifact_resolving_service import ArtifactResolvingService
from app.services.saml.saml_identity_provider_service import SamlIdentityProviderService
from app.services.saml.saml_response_factory import SAMLResponseFactory
from app.services.userinfo.userinfo_service import UserinfoService
from app.storage.authentication_cache import AuthenticationCache


# pylint:disable=too-many-arguments
class OIDCProvider:
    def __init__(
        self,
        pyop_provider: PyopProvider,
        authentication_cache: AuthenticationCache,
        rate_limiter: RateLimiter,
        clients: dict,
        saml_identity_provider_service: SamlIdentityProviderService,
        mock_digid: bool,
        saml_response_factory: SAMLResponseFactory,
        artifact_resolving_service: ArtifactResolvingService,
        userinfo_service: UserinfoService,
        app_mode: str,
        environment: str,
    ):
        if mock_digid and environment.startswith("prod"):
            raise ValueError(
                f"Unable to enable mock_digid for environment {environment}"
            )
        self._pyop_provider = pyop_provider
        self._authentication_cache = authentication_cache
        self._rate_limiter = rate_limiter
        self._clients = clients
        self._saml_identity_provider_service = saml_identity_provider_service
        self._mock_digid = mock_digid
        self._saml_response_factory = saml_response_factory
        self._artifact_resolving_service = artifact_resolving_service
        self._userinfo_service = userinfo_service
        self._app_mode = app_mode
        self._environment = environment

    def well_known(self):
        return JSONResponse(
            content=jsonable_encoder(
                self._pyop_provider.provider_configuration.to_dict()
            )
        )

    def jwks(self):
        return JSONResponse(content=jsonable_encoder(self._pyop_provider.jwks))

    def authorize(self, authorize_request: AuthorizeRequest, request: Request):
        self._validate_authorize_request(authorize_request)
        self._rate_limiter.validate_outage()

        pyop_authentication_request = (
            self._pyop_provider.parse_authentication_request(  # type:ignore
                urlencode(authorize_request.dict()), request.headers
            )
        )

        if request.client is None or request.client.host is None:
            raise ServerErrorException(
                "No Client info available in the request content"
            )
        identity_provider_name = (
            self._rate_limiter.get_identity_provider_name_and_validate_request(
                request.client.host
            )
        )

        saml_identity_provider = (
            self._saml_identity_provider_service.get_identity_provider(
                identity_provider_name
            )
        )
        randstate = self._authentication_cache.create_authentication_request_state(
            pyop_authentication_request, authorize_request, identity_provider_name
        )

        login_digid_request = LoginDigiDRequest(
            state=randstate, authorize_request=authorize_request
        )

        return self._saml_response_factory.create_saml_response(
            self._mock_digid, saml_identity_provider, login_digid_request, randstate
        )

    def token(self, token_request: TokenRequest, headers: Headers) -> Response:
        acs_context = self._authentication_cache.get_acs_context(token_request.code)
        if acs_context is None:
            raise HTTPException(
                400, detail="Code challenge has expired. Please retry authorization."
            )

        token_response = self._pyop_provider.handle_token_request(  # type:ignore
            token_request.query_string, headers
        )
        resolved_artifact = self._artifact_resolving_service.resolve_artifact(
            acs_context
        )
        userinfo = self._userinfo_service.request_userinfo_for_artifact(
            acs_context, resolved_artifact
        )
        self._authentication_cache.cache_authentication_context(
            token_response, userinfo
        )
        return token_response

    def userinfo(self, request: Request):
        bearer_token = extract_bearer_token_from_http_request(
            authz_header=request.headers.get("Authorization")
        )
        if self._app_mode == "legacy":
            authentication_context = (
                self._authentication_cache.get_authentication_context(bearer_token)
            )
            introspection = (
                self._pyop_provider.authz_state.introspect_access_token(  # type:ignore
                    authentication_context["access_token"]
                )
            )
        else:
            # todo: id_token valid until same as redis cache ttl
            introspection = (
                self._pyop_provider.authz_state.introspect_access_token(  # type:ignore
                    bearer_token
                )
            )
            authentication_context = (
                self._authentication_cache.get_authentication_context(bearer_token)
            )

        if not introspection["active"]:
            raise Exception("not authorized")
        return Response(
            headers={"Content-Type": "application/jwt"},
            content=authentication_context["external_user_authentication_context"],
        )

    def _validate_authorize_request(self, authorize_request: AuthorizeRequest):
        """
        Validate the authorization request. If client_id or redirect_uri is invalid, we cannot redirect the
        user. Instead, return a 400 should be returned.
        """
        if authorize_request.client_id not in self._clients:
            raise InvalidClientException()

        if authorize_request.redirect_uri not in self._clients[
            authorize_request.client_id
        ].get("redirect_uris", []):
            raise InvalidRedirectUriException()
