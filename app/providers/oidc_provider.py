import json
import logging
import secrets
from typing import List, Union, Dict, Any
from urllib import parse
from urllib.parse import urlencode, urlunparse, ParseResult

from fastapi import Request, HTTPException, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from jwcrypto.jwt import JWT
from pyop.message import AuthorizationRequest
from pyop.provider import AuthorizationResponse, extract_bearer_token_from_http_request
from starlette.datastructures import Headers

from app.exceptions.max_exceptions import (
    ServerErrorException,
    UnauthorizedError,
    InvalidClientException,
    InvalidRedirectUriException,
    InvalidResponseType,
)
from app.models.authentication_meta import AuthenticationMeta
from app.models.login_method import LoginMethod, LoginMethodWithLink
from app.providers.pyop_provider import MaxPyopProvider
from app.exceptions.oidc_exceptions import LOGIN_REQUIRED
from app.misc.rate_limiter import RateLimiter
from app.models.acs_context import AcsContext
from app.models.authentication_context import AuthenticationContext
from app.models.authorize_request import AuthorizeRequest
from app.models.token_request import TokenRequest
from app.services.loginhandler.exchange_based_authentication_handler import (
    ExchangeBasedAuthenticationHandler,
)
from app.services.template_service import TemplateService
from app.services.loginhandler.authentication_handler_factory import (
    AuthenticationHandlerFactory,
)
from app.services.response_factory import ResponseFactory
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.userinfo.userinfo_service import UserinfoService
from app.storage.authentication_cache import AuthenticationCache
from app.validators.token_authentication_validator import TokenAuthenticationValidator


logger = logging.getLogger(__name__)


# pylint:disable=too-many-arguments
class OIDCProvider:  # pylint:disable=too-many-instance-attributes
    def __init__(
        self,
        pyop_provider: MaxPyopProvider,
        authentication_cache: AuthenticationCache,
        rate_limiter: RateLimiter,
        clients: Dict[str, Dict[str, Any]],
        saml_response_factory: SamlResponseFactory,
        response_factory: ResponseFactory,
        userinfo_service: UserinfoService,
        app_mode: str,
        environment: str,
        login_methods: List[LoginMethod],
        authentication_handler_factory: AuthenticationHandlerFactory,
        external_base_url: str,
        external_http_requests_timeout_seconds: int,
        login_options_sidebar_template: str,
        template_service: TemplateService,
        allow_wildcard_redirect_uri: bool,
        token_authentication_validator: TokenAuthenticationValidator,
    ):
        self._pyop_provider = pyop_provider
        self._authentication_cache = authentication_cache
        self._rate_limiter = rate_limiter
        self._clients = clients
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
        self._external_http_requests_timeout_seconds = (
            external_http_requests_timeout_seconds
        )
        self._login_options_sidebar_template = login_options_sidebar_template
        self._template_service = template_service
        self._allow_wildcard_redirect_uri = allow_wildcard_redirect_uri
        self._token_authentication_validator = token_authentication_validator

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
        client = self._clients[authorize_request.client_id]
        login_options = self._get_login_methods(client, authorize_request)
        login_options_response = self._provide_login_options_response(
            client["name"], request, login_options
        )
        if login_options_response:
            return login_options_response
        return self._authorize(request, authorize_request, login_options[0])

    def _create_pyop_authentication_request(
        self, request: Request, authorize_request: AuthorizeRequest
    ) -> AuthorizationRequest:
        return self._pyop_provider.parse_authentication_request(
            urlencode(
                {
                    "client_id": authorize_request.client_id,
                    "redirect_uri": authorize_request.redirect_uri,
                    "response_type": authorize_request.response_type,
                    "nonce": authorize_request.nonce,
                    "scope": authorize_request.scope,
                    "state": authorize_request.state,
                    "code_challenge": authorize_request.code_challenge,
                    "code_challenge_method": authorize_request.code_challenge_method,
                }
            ),
            request.headers,
        )

    def _authorize(
        self,
        request: Request,
        authorize_request: AuthorizeRequest,
        login_method: LoginMethod,
    ) -> Response:
        self._rate_limiter.validate_outage()

        pyop_authentication_request = self._create_pyop_authentication_request(
            request, authorize_request
        )

        if request.client is None or request.client.host is None:
            raise ServerErrorException(
                error_description="No Client info available in the request content"
            )

        self._rate_limiter.ip_limit_test(request.client.host)

        login_handler = self._authentication_handler_factory.create(login_method)

        authentication_state = login_handler.authentication_state(authorize_request)

        randstate = self._authentication_cache.create_randstate(
            pyop_authentication_request, authorize_request
        )

        authorize_response = login_handler.authorize_response(
            request,
            authorize_request,
            pyop_authentication_request,
            authentication_state,
            randstate,
        )

        session_id = (
            authorize_response.session_id
            if authorize_response.session_id
            else secrets.token_urlsafe(32)
        )

        authentication_meta = AuthenticationMeta.create_authentication_meta(
            request, login_method
        )

        self._authentication_cache.cache_authentication_request_state(
            pyop_authentication_request,
            authorize_request,
            randstate,
            authentication_state,
            login_method.name,
            session_id,
            req_acme_tokens=authorize_request.acme_tokens,
            authentication_meta=authentication_meta,
        )

        return authorize_response.response

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
        self,
        authentication_request: AuthenticationContext,
        userinfo: str,
        pyop_authorize_response: AuthorizationResponse,
    ):
        auth_req = authentication_request.authorization_request

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
        client = self._clients.get(token_request.client_id)
        if client is None:
            raise InvalidClientException(error_description="unknown client")

        self._token_authentication_validator.validate_client_authentication(
            client_id=token_request.client_id,
            client=client,
            client_assertion_jwt=token_request.client_assertion,
            client_assertion_type=token_request.client_assertion_type,
        )

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
                raise UnauthorizedError(error_description="not authorized")
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
                raise UnauthorizedError(error_description="not authorized")

        if not introspection["active"] or not userinfo_context:
            raise UnauthorizedError(error_description="not authorized")

        return Response(
            headers={
                "Content-Type": "application/jwt",
                "Authentication-Method": userinfo_context.authentication_method,
            },
            content=userinfo_context.userinfo,
        )

    def authenticate_with_exchange_token(
        self, state: str, incoming_exchange_token: str
    ):
        authentication_context = self.get_authentication_request_state(state)
        exchange_token = authentication_context.authentication_state["exchange_token"]
        if exchange_token != incoming_exchange_token:
            raise UnauthorizedError(error_description="Authentication Failed")

        login_method = next(
            (
                login_method
                for login_method in self._login_methods
                if login_method.name == authentication_context.authentication_method
            )
        )
        login_handler = self._authentication_handler_factory.create(login_method)
        if not isinstance(login_handler, ExchangeBasedAuthenticationHandler):
            raise ServerErrorException(
                error_description="Incorrect login method assigned"
            )
        external_session_status = login_handler.get_external_session_status(
            exchange_token
        )

        if external_session_status != "DONE":
            # Login aborted by user
            raise UnauthorizedError(
                error=LOGIN_REQUIRED, error_description="Authentication cancelled"
            )

        pyop_authorization_response = self.py_op_authorize(
            authentication_context.authorization_request
        )
        subject = self.get_subject_identifier(pyop_authorization_response["code"])
        userinfo = self._userinfo_service.request_userinfo_for_exchange_token(
            authentication_context, subject
        )

        return self.authenticate(
            authentication_context, userinfo, pyop_authorization_response
        )

    def authenticate(
        self,
        authentication_context: AuthenticationContext,
        userinfo: str,
        pyop_authorization_response: AuthorizationResponse,
    ):
        response_url = self.handle_external_authentication(
            authentication_context, userinfo, pyop_authorization_response
        )
        return self._response_factory.create_redirect_response(response_url)

    def _get_login_methods(
        self, client: dict, authorize_request: AuthorizeRequest
    ) -> List[LoginMethod]:
        login_methods = self._login_methods

        if "login_methods" in client:
            login_methods = [
                x for x in login_methods if x.name in client["login_methods"]
            ]

        if "exclude_login_methods" in client:
            login_methods = [
                x
                for x in login_methods
                if x.name not in client["exclude_login_methods"]
            ]

        requested_login_methods = [
            x for x in login_methods if x.name in authorize_request.login_hints
        ]

        return requested_login_methods if requested_login_methods else login_methods

    def _provide_login_options_response(
        self,
        client_name: str,
        request: Request,
        login_methods: List[LoginMethod],
    ) -> Union[None, Response]:
        if len(login_methods) > 1:
            login_methods_by_name = self._get_login_method_links_by_name(
                request_url=str(request.url), login_methods=login_methods
            )

            redirect_url_parts = parse.urlparse(request.query_params["redirect_uri"])
            query = dict(parse.parse_qsl(redirect_url_parts.query))
            query.update(
                {
                    "error": "login_required",
                    "error_description": "Authentication cancelled",
                }
            )
            page_context = {
                "ura_name": client_name,
                "login_methods": login_methods_by_name,
                "redirect_uri": redirect_url_parts._replace(
                    query=parse.urlencode(query)
                ).geturl(),
            }
            return self._template_service.render_layout(
                request=request,
                template_name="login_options.html",
                page_title=f"{client_name} - Inlogmethode selecteren",
                page_context=page_context,
                sidebar_template=self._login_options_sidebar_template,
            )

        if len(login_methods) != 1:
            raise UnauthorizedError(
                error_description="No valid login_methods available"
            )
        return None

    def _validate_authorize_request(self, authorize_request: AuthorizeRequest):
        """
        Validate the authorization request. If client_id or redirect_uri is invalid, we cannot redirect the
        user. Instead, a 400 should be returned.
        """
        if authorize_request.client_id not in self._clients:
            raise InvalidClientException(
                error_description=f"Client id {authorize_request.client_id} is not known for this OIDC server"
            )

        client = self._clients[authorize_request.client_id]
        if not self._redirect_uri_is_valid(client, authorize_request.redirect_uri):
            raise InvalidRedirectUriException()

        if authorize_request.response_type not in client.get("response_types", []):
            raise InvalidResponseType()

    def _redirect_uri_is_valid(self, client: dict, redirect_uri: str) -> bool:
        redirect_uris = client.get("redirect_uris", [])

        return redirect_uri in redirect_uris or (
            self._allow_wildcard_redirect_uri
            and "*" in redirect_uris
            and not self._environment.startswith("prod")
        )

    def get_subject_identifier(self, authorization_code: str) -> str:
        """
        Wrapper method to use Pyop service and sub with authorization code
        """
        return self._pyop_provider.get_subject_identifier_from_authz_state(
            authorization_code
        )

    def py_op_authorize(
        self, authorization_request: AuthorizationRequest
    ) -> AuthorizationResponse:
        """
        Wrapper method to expose pyop authorization method.
        """
        return self._pyop_provider.authorize(authorization_request, "_")

    def _get_url_for_login_method(
        self,
        parsed_url: ParseResult,
        base_url: ParseResult,
        query_params: Dict[str, List[str]],
        login_method_name: str,
    ) -> str:
        query_params["login_hint"] = [login_method_name]
        updated_query = urlencode(query_params, doseq=True)
        combined_path = base_url.path + parsed_url.path
        updated_url = urlunparse(
            (
                base_url.scheme,
                base_url.netloc,
                combined_path,
                parsed_url.params,
                updated_query,
                parsed_url.fragment,
            )
        )
        return updated_url

    def _get_login_method_links_by_name(
        self, request_url: str, login_methods: List[LoginMethod]
    ) -> Dict[str, LoginMethodWithLink]:
        base_url = parse.urlparse(self._external_base_url)

        parsed_url = parse.urlparse(request_url)
        query_params = parse.parse_qs(parsed_url.query)

        login_methods_dict = {}
        for login_method in login_methods:
            login_methods_dict[login_method.name] = LoginMethodWithLink(
                **login_method.dict(),
                url=self._get_url_for_login_method(
                    parsed_url, base_url, query_params, login_method.name
                ),
            )

        return login_methods_dict
