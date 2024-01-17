import json
import secrets
from typing import List, Union, Dict
from urllib import parse
from urllib.parse import urlencode, urlunparse

import requests
from fastapi import Request, HTTPException, Response
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from jwcrypto.jwt import JWT
from pyop.message import AuthorizationRequest
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
    InvalidResponseType,
)
from app.exceptions.oidc_exceptions import LOGIN_REQUIRED
from app.misc.rate_limiter import RateLimiter
from app.models.acs_context import AcsContext
from app.models.authentication_context import AuthenticationContext
from app.models.authorize_request import AuthorizeRequest
from app.models.token_request import TokenRequest
from app.services.template_service import TemplateService
from app.services.loginhandler.authentication_handler_factory import (
    AuthenticationHandlerFactory,
)
from app.services.response_factory import ResponseFactory
from app.services.saml.saml_response_factory import SamlResponseFactory
from app.services.userinfo.userinfo_service import UserinfoService
from app.storage.authentication_cache import AuthenticationCache


# pylint:disable=too-many-arguments
class OIDCProvider:  # pylint:disable=too-many-instance-attributes
    def __init__(
        self,
        pyop_provider: PyopProvider,
        authentication_cache: AuthenticationCache,
        rate_limiter: RateLimiter,
        clients: dict,
        saml_response_factory: SamlResponseFactory,
        response_factory: ResponseFactory,
        userinfo_service: UserinfoService,
        app_mode: str,
        environment: str,
        login_methods: List[Dict[str, str]],
        authentication_handler_factory: AuthenticationHandlerFactory,
        external_base_url: str,
        session_url: str,
        external_http_requests_timeout_seconds: int,
        sidebar_template: str,
        template_service: TemplateService,
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
        self._session_url = session_url
        self._pyop_provider.configuration_information[
            "code_challenge_methods_supported"
        ] = ["S256"]
        self._external_http_requests_timeout_seconds = (
            external_http_requests_timeout_seconds
        )
        self._sidebar_template = sidebar_template
        self._template_renderer = template_service.templates

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
        login_option: Dict[str, str],
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

        login_handler = self._authentication_handler_factory.create(login_option)

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

        self._authentication_cache.cache_authentication_request_state(
            pyop_authentication_request,
            authorize_request,
            randstate,
            authentication_state,
            login_option["name"],
            session_id,
            req_acme_tokens=authorize_request.acme_tokens,
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
        self, authentication_request: AuthenticationContext, userinfo: str
    ):
        auth_req = authentication_request.authorization_request
        pyop_authorize_response = self._pyop_provider.authorize(  # type:ignore
            auth_req, "_"
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

    def authenticate_with_exchange_token(self, state: str):
        authentication_context = self.get_authentication_request_state(state)
        exchange_token = authentication_context.authentication_state["exchange_token"]
        external_session_status = requests.get(
            f"{self._session_url}/{exchange_token}/status",
            headers={"Content-Type": "text/plain"},
            timeout=self._external_http_requests_timeout_seconds,
        )
        if external_session_status.status_code != 200:
            raise UnauthorizedError(error_description="Authentication failed")
        if external_session_status.json() != "DONE":
            # Login aborted by user
            raise UnauthorizedError(
                error=LOGIN_REQUIRED, error_description="Authentication cancelled"
            )

        userinfo = self._userinfo_service.request_userinfo_for_exchange_token(
            authentication_context
        )
        return self.authenticate(authentication_context, userinfo)

    def authenticate(self, authentication_context, userinfo):
        response_url = self.handle_external_authentication(
            authentication_context, userinfo
        )
        return self._response_factory.create_redirect_response(response_url)

    def _get_login_methods(
        self, client: dict, authorize_request: AuthorizeRequest
    ) -> List[Dict[str, str]]:
        login_methods = self._login_methods

        if "login_methods" in client:
            login_methods = [
                x for x in login_methods if x["name"] in client["login_methods"]
            ]

        if "exclude_login_methods" in client:
            login_methods = [
                x
                for x in login_methods
                if x["name"] not in client["exclude_login_methods"]
            ]

        requested_login_methods = [
            x for x in login_methods if x["name"] in authorize_request.login_hints
        ]

        return requested_login_methods if requested_login_methods else login_methods

    def _provide_login_options_response(
        self,
        client_name: str,
        request: Request,
        login_methods: List[Dict[str, str]],
    ) -> Union[None, Response]:
        if len(login_methods) > 1:
            parsed_url = parse.urlparse(str(request.url))
            base_url = parse.urlparse(self._external_base_url)

            query_params = parse.parse_qs(parsed_url.query)

            for login_method in login_methods:
                query_params["login_hint"] = [login_method["name"]]
                updated_query = urlencode(query_params, doseq=True)
                updated_url = urlunparse(
                    (
                        base_url.scheme,
                        base_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        updated_query,
                        parsed_url.fragment,
                    )
                )
                login_method["url"] = updated_url

            login_method_by_name = {x["name"]: x for x in login_methods}

            redirect_url_parts = parse.urlparse(request.query_params["redirect_uri"])
            query = dict(parse.parse_qsl(redirect_url_parts.query))
            query.update(
                {
                    "error": "login_required",
                    "error_description": "Authentication cancelled",
                }
            )
            template_context = {
                "request": request,
                "layout": "layout.html",
                "ura_name": client_name,
                "login_methods": login_method_by_name,
                "redirect_uri": redirect_url_parts._replace(
                    query=parse.urlencode(query)
                ).geturl(),
            }
            if self._sidebar_template:
                template_context["sidebar"] = self._sidebar_template

            return self._template_renderer.TemplateResponse(
                "login_options.html", template_context
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

        if authorize_request.redirect_uri not in self._clients[
            authorize_request.client_id
        ].get("redirect_uris", []):
            raise InvalidRedirectUriException()
        if authorize_request.response_type not in self._clients[
            authorize_request.client_id
        ].get("response_types", []):
            raise InvalidResponseType()
