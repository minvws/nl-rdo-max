import json
from typing import List, Union
from urllib.parse import urlencode

from fastapi import Request, HTTPException, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from jwcrypto.jwt import JWT
from pyop.provider import (  # type: ignore[attr-defined]
    Provider as PyopProvider,
    extract_bearer_token_from_http_request,
)
from starlette.datastructures import Headers

from app.exceptions.max_exceptions import (
    ServerErrorException,
    UnauthorizedError,
    InvalidClientException,
    InvalidRedirectUriException,
)
from app.misc.rate_limiter import RateLimiter
from app.models.acs_context import AcsContext
from app.models.authentication_context import AuthenticationContext
from app.models.authorize_request import AuthorizeRequest
from app.models.token_request import TokenRequest
from app.services.loginhandler.authentication_handler_factory import (
    AuthenticationHandlerFactory,
)
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.response_factory import ResponseFactory

from app.services.userinfo.userinfo_service import UserinfoService
from app.storage.authentication_cache import AuthenticationCache

templates = Jinja2Templates(directory="jinja2")


# pylint:disable=too-many-arguments
class OIDCProvider:  # pylint:disable=too-many-instance-attributes
    def __init__(
        self,
        pyop_provider: PyopProvider,
        authentication_cache: AuthenticationCache,
        rate_limiter: RateLimiter,
        clients: dict,
        mock_digid: bool,
        saml_response_factory: SamlResponseFactory,
        response_factory: ResponseFactory,
        userinfo_service: UserinfoService,
        app_mode: str,
        environment: str,
        login_methods: List[str],
        authentication_handler_factory: AuthenticationHandlerFactory,
        external_base_url: str,
    ):
        if mock_digid and environment.startswith("prod"):
            raise ValueError(
                f"Unable to enable mock_digid for environment {environment}"
            )
        self._pyop_provider = pyop_provider
        self._authentication_cache = authentication_cache
        self._rate_limiter = rate_limiter
        self._clients = clients
        self._mock_digid = mock_digid
        self._saml_response_factory = saml_response_factory
        self._response_factory = response_factory
        self._userinfo_service = userinfo_service
        self._app_mode = app_mode
        self._environment = environment
        self._login_methods = login_methods
        self._authentication_handler_factory = authentication_handler_factory
        self._external_base_url = external_base_url
        self._pyop_provider.configuration_information[
            "code_challenge_methods_supported"
        ] = ["S256"]

    def well_known(self):
        return JSONResponse(
            content=jsonable_encoder(
                self._pyop_provider.provider_configuration.to_dict()
            )
        )

    def jwks(self):
        return JSONResponse(content=jsonable_encoder(self._pyop_provider.jwks))

    def present_login_options_or_authorize(
        self, request: Request, authorize_request: AuthorizeRequest
    ):
        self._validate_authorize_request(authorize_request)
        login_options = self._get_login_methods(authorize_request)
        login_options_response = self._provide_login_options_response(
            request, authorize_request, login_options
        )
        if login_options_response:
            return login_options_response
        return self._authorize(request, authorize_request, login_options[0])

    def _authorize(
        self, request: Request, authorize_request: AuthorizeRequest, login_option: str
    ) -> Response:
        self._rate_limiter.validate_outage()
        pyop_authentication_request = (
            self._pyop_provider.parse_authentication_request(  # type:ignore
                urlencode(authorize_request.dict()), request.headers
            )
        )

        if request.client is None or request.client.host is None:
            raise ServerErrorException(
                error_description="No Client info available in the request content"
            )

        self._rate_limiter.ip_limit_test(request.client.host)

        login_handler = self._authentication_handler_factory.create(login_option)

        authentication_state = login_handler.authentication_state(authorize_request)

        randstate = self._authentication_cache.create_authentication_request_state(
            pyop_authentication_request,
            authorize_request,
            authentication_state,
            login_option,
        )

        return login_handler.authorize_response(
            request,
            authorize_request,
            pyop_authentication_request,
            authentication_state,
            randstate,
        )

    def get_authentication_request_state(self, randstate: str) -> AuthenticationContext:
        authentication_request = (
            self._authentication_cache.get_authentication_request_state(randstate)
        )
        if authentication_request is None:
            raise UnauthorizedError(
                error_description="No active login state found for this request."
            )
        return authentication_request

    def handle_external_authentication(
        self, authentication_request: AuthenticationContext, userinfo: str
    ):
        auth_req = authentication_request.authorization_request

        # TODO: Change this to client from clients.json, if possible
        pyop_authorize_response = self._pyop_provider.authorize(  # type:ignore
            auth_req, "client"
        )

        acs_context = AcsContext(
            client_id=authentication_request.authorization_request["client_id"],
            authentication_method=authentication_request.authentication_method,
            authentication_state=authentication_request.authentication_state,
            userinfo=userinfo,
        )
        self._authentication_cache.cache_acs_context(
            pyop_authorize_response["code"], acs_context
        )

        response_url = pyop_authorize_response.request(auth_req["redirect_uri"], False)

        return response_url

    def token(self, token_request: TokenRequest, headers: Headers) -> Response:
        acs_context = self._authentication_cache.get_acs_context(token_request.code)
        if acs_context is None:
            raise HTTPException(
                400, detail="Code challenge has expired. Please retry authorization."
            )

        token_response = self._pyop_provider.handle_token_request(  # type:ignore
            token_request.query_string, headers
        )

        if self._app_mode == "legacy":
            id_jwt = JWT.from_jose_token(token_response["id_token"])
            at_hash_key = json.loads(id_jwt.token.objects["payload"].decode("utf-8"))[
                "at_hash"
            ]
            self._authentication_cache.cache_userinfo_context(
                at_hash_key, token_response["access_token"], acs_context
            )
        else:
            self._authentication_cache.cache_userinfo_context(
                token_response["access_token"],
                token_response["access_token"],
                acs_context,
            )
        return token_response

    def userinfo(self, request: Request):
        bearer_token = extract_bearer_token_from_http_request(
            authz_header=request.headers.get("Authorization")
        )
        if self._app_mode == "legacy":
            id_jwt = JWT.from_jose_token(bearer_token)
            at_hash_key = json.loads(id_jwt.token.objects["payload"].decode("utf-8"))[
                "at_hash"
            ]
            userinfo_context = self._authentication_cache.get_userinfo_context(
                at_hash_key
            )
            if not userinfo_context:
                raise Exception("not authorized")
            introspection = (
                self._pyop_provider.authz_state.introspect_access_token(  # type:ignore
                    userinfo_context.access_token
                )
            )
        else:
            # todo: id_token valid until same as redis cache ttl
            introspection = (
                self._pyop_provider.authz_state.introspect_access_token(  # type:ignore
                    bearer_token
                )
            )
            userinfo_context = self._authentication_cache.get_userinfo_context(
                bearer_token
            )
            if not userinfo_context:
                raise Exception("not authorized")
        if not introspection["active"] or not userinfo_context:
            raise Exception("not authorized")
        return Response(
            headers={
                "Content-Type": "application/jwt",
                "Authentication-Method": userinfo_context.authentication_method,
            },
            content=userinfo_context.userinfo,
        )

    def continue_flow(self, state: str):
        authentication_context = self.get_authentication_request_state(state)

        userinfo = self._userinfo_service.request_userinfo_for_exchange_token(
            authentication_context,
            authentication_context.authentication_state["exchange_token"],
        )
        return self.authenticate(authentication_context, userinfo)

    def authenticate(self, authentication_context, userinfo):
        response_url = self.handle_external_authentication(
            authentication_context, userinfo
        )
        return self._response_factory.create_redirect_response(response_url)

    def _get_login_methods(self, authorize_request: AuthorizeRequest) -> List[str]:
        login_methods = [
            x for x in self._login_methods if x in authorize_request.login_hints
        ]
        if not login_methods:
            return self._login_methods
        return login_methods

    def _provide_login_options_response(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        login_methods: List[str],
    ) -> Union[None, Response]:
        if len(login_methods) > 1:
            redirect_url = request.url.remove_query_params("login_hints")
            return templates.TemplateResponse(
                "login_options.html",
                {
                    "request": request,
                    "login_methods": login_methods,
                    "ura_name": self._clients[authorize_request.client_id]["name"],
                    "redirect_uri": f"{self._external_base_url}{redirect_url.path}?{redirect_url.query}",
                },
            )
        if len(login_methods) != 1:
            raise UnauthorizedError(
                error_description="No valid login_methods available"
            )
        return None

    def _validate_authorize_request(self, authorize_request: AuthorizeRequest):
        """
        Validate the authorization request. If client_id or redirect_uri is invalid, we cannot redirect the
        user. Instead, return a 400 should be returned.
        """
        if authorize_request.client_id not in self._clients:
            raise InvalidClientException(
                error_description=f"Client id {authorize_request.client_id} is not known for this OIDC server"
            )

        if authorize_request.redirect_uri not in self._clients[
            authorize_request.client_id
        ].get("redirect_uris", []):
            raise InvalidRedirectUriException()
