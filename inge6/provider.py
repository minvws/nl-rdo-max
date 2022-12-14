# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
# pylint: disable=anomalous-backslash-in-string
"""
module: inge6/provider.py
summary: provide a OIDC interface for OIDC clients to connect to a SAML provider. The core of Inge6



                                                        ------------------
                                              / - - - >| SorryTooBusyPage |
                                              |         ------------------
                                      | R |   |
        /-------------\               | A |   |         /-------------\ Redirect/POST       /-------------------\
        |             |   /authorize  | T |   |         |             |  end-user to login  |       SAML        |
        |             | --------------| E |---*-------->|             |-------------------->|    IDProvider     |
        |             |               | L |             |             |     Artifact        |                   |
        |             |               | I |             |             |<--------------------| (e.g. DigiD/TVS)  |
        |             |               | M |             |             |                     \-------------------/
        |             |               | I |             |             |                             ^   |
        |             |               | T |             |             |                             |   |
        |    Some     |                                 |    Inge6    |                             |   |
        | OIDC-Client |          response=code          | OIDC-Server |                             |   |
        |             |<------------------------------- |   Provider  |                             |   | response=BSN
        |             |                                 |             |                             |   |
        |             |  /accesstoken                   |             |                             |   |
        |             |-------------------------------->|             |     GET resolve_artifact    |   |
        |             |                                 |             |-----------------------------/   |
        |             |                                 |             |                                 |
        |             |        response=JWT Token       |             |<--------------------------------/
        |             |<--------------------------------|             |
        |             |                                 |             |
        \-------------/                                 \-------------/
                                                               ^
                                                               |
                                                               |
                                                               |
                                                               V
                                                        /-------------\
                                                        |             |
                                                        | Redis Cache |
                                                        |             |
                                                        \-------------/

The depicted figure does not contain all requests, and is merely intended for a general/summary overview of the communcation with
defined modules.

The provider defined in this file is the core of Inge6, it handles all the OIDC requests. Initiating requests to the
Identity Providers for third-party end-user logins, resolving artifacts and using the Redis Cache to track the users activity
over time.

required:
    - Configured a redis server
    - settings.redis
    - settings.ratelimiter
    - settings.identity providers

    - settings.issuer, issuer of the tokens
    - settings.authorize_endpoint, endpoint used for initiating an authorization request.

"""
import base64

import json
import logging
from logging import Logger

from urllib.parse import urlparse
from urllib.parse import parse_qs, urlencode

from typing import Union, Dict, Any
from pydantic.main import BaseModel

import requests

import nacl.hash

from starlette.datastructures import Headers

from fastapi import Request, Response, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

from oic.oic.message import TokenErrorResponse
from pyop.exceptions import (
    InvalidAuthenticationRequest,
    InvalidClientAuthentication,
    OAuthError,
)

from onelogin.saml2.auth import OneLogin_Saml2_Auth

from inge6.conf import settings as defaults  # type: ignore
from . import constants
from .cache import RedisCache
from .config import Settings, get_settings
from .rate_limiter import RateLimiter
from .utils import (
    create_redis_bsn_key,
    cache_auth_req,
    cache_code_challenge,
    cache_artifact,
    hget_from_redis,
    validate_auth_req,
)

from .encrypt import Encrypt
from .models import (
    AuthorizeRequest,
    JWTError,
    JWTResponse,
    LoginDigiDRequest,
    MetaRedirectResponse,
    SAMLAuthNAutoSubmitResponse,
    SomethingWrongHTMLResponse,
    SorryPageRequest,
)

from .exceptions import (
    AuthorizationByProxyDisabled,
    AuthorizeEndpointException,
    DependentServiceOutage,
    TokenSAMLErrorResponse,
    ExpiredResourceError,
    UnexpectedAuthnBinding,
    ExpectedRedisValue,
)

from .saml.exceptions import ScopingAttributesNotAllowed, UserNotAuthenticated
from .saml.id_provider import IdProvider
from .saml.provider import Provider as SAMLProvider
from .saml import ArtifactResponse

from .oidc.provider import Provider as OIDCProvider
from .oidc.storage import RedisWrapper
from .oidc.authorize import (
    is_authorized,
    accesstoken,
)


def _get_too_busy_redirect_error_uri(redirect_uri, state, uri_allow_list):
    """
    Given the redirect uri and state, return an error to the client desribing the service
    is too busy to handle an authorize request.

        redirect_uri?error=login_required&error_description=The+servers+are+too+busy+right+now,+please+try+again+later&state=34Gf3431D

    :param redirect_uri: uri to pass the error query params to
    :param state: state that corresponds to the request

    """
    if redirect_uri not in uri_allow_list:
        return "https://coronacheck.nl"

    error = "login_required"
    error_desc = "The servers are too busy right now, please try again later."
    return redirect_uri + f"?error={error}&error_description={error_desc}&state={state}"


def _get_bsn_from_art_resp(bsn_response: str, id_provider: IdProvider) -> str:
    """
    Depending on the saml versioning the bsn is or is not prepended with a sectore code.

    For saml specification 4.4 and 4.5 the bsn is encrypted, and not prepended with such codes.
    For saml specification 3.5 the bsn is prepended with a sector_code representing its value to
    be either a BSN number or SOFI number.
    """

    if id_provider.saml_is_new_version:
        return bsn_response

    if id_provider.saml_is_legacy_version:
        sector_split = bsn_response.split(":")
        sector_number = constants.SECTOR_CODES[sector_split[0]]
        if sector_number != constants.SectorNumber.BSN:
            raise ValueError(f"Expected BSN number, received: {sector_number}")
        return sector_split[1]

    raise ValueError("Unknown SAML specification, known: 3.5, >=4.4")


def _perform_artifact_resolve_request(artifact: str, id_provider: IdProvider):
    """
    Perform an artifact resolve request using the provided artifact and identity provider.
    The identity provider tells us the locations of the endpoints needed for resolving the artifact,
    and the artifact is needed for the provider to resolve the requested attribute.
    """
    url = id_provider.idp_metadata.get_artifact_rs()["location"]
    resolve_artifact_req = id_provider.create_artifactresolve_request(artifact)
    headers = {"SOAPAction": "resolve_artifact", "content-type": "text/xml"}

    return requests.post(
        url,
        headers=headers,
        data=resolve_artifact_req.get_xml(xml_declaration=True),
        cert=(id_provider.cert_path, id_provider.key_path),
        timeout=60,
    )


class Provider(SAMLProvider):  # pylint: disable=R0902
    """
    This provider is the bridge between OIDC and SAML. It implements the OIDC protocol
    and connects to a configured SAML provider.

    Required grant_types = authorization_code
    Required PKCE implementation by client (only supporting 'public' clients: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1)


    Required settings:
        - settings.ratelimit.sorry_too_busy_page_head, head part HTML sorry-too-busy-page
        - settings.ratelimit.sorry_too_busy_page_tail, tail part HTML sorry-too-busy-page

        - `settings.primary_idp_key`: Primary IDP to be used. Make sure this IDP is also configured in the
        Identity Providers JSON file, path configured in the `settings.saml.identity_provider_settings`.
        - `settings.oidc.clients_file`: file containing the registered clients and their OIDC configuration.
        - `settings.bsn.sign_key`: private key used for signing the transmitted BSN
        - `settings.bsn.encrypt_key`: public key used for encrypting the transmitted BSN
        - `settings.bsn.local_symm_key`: symmetric key used for encrypting the BSN stored in the Redis-store
    """

    @property
    def clients(self) -> dict:
        return self.oidc.clients

    @clients.setter
    def clients(self, value: dict):
        self.oidc.clients = value

    @property
    def provider_configuration(self):
        return self.oidc.provider_configuration

    @property
    def key(self):
        return self.oidc.key

    @staticmethod
    def cache_factory(settings, redis_client=None):
        return RedisCache(settings=settings, redis_client=redis_client)

    def __init__(self, settings: Settings = get_settings(), redis_client=None) -> None:
        SAMLProvider.__init__(self, settings)
        self.redis_cache = self.cache_factory(
            settings=settings, redis_client=redis_client
        )
        self.redis_client = self.redis_cache.redis_client
        assert redis_client is None or (redis_client == self.redis_client)
        self.oidc = OIDCProvider.fromsettings(
            settings=defaults,
            storage_factory=lambda **kwargs: RedisWrapper(
                redis_client=self.redis_client, **kwargs
            ),
            redis_cache=self.redis_cache,
        )
        self.settings = settings

        logging.basicConfig(
            level=getattr(logging, settings.loglevel.upper()),
            datefmt="%m/%d/%Y %I:%M:%S %p",
        )
        self.log: Logger = logging.getLogger(__package__)

        self.bsn_encrypt = Encrypt(
            raw_sign_key=settings.bsn.i6_sign_privkey,
            raw_enc_key=settings.bsn.i4_encrypt_pubkey,
            raw_local_enc_key=settings.bsn.local_symm_key,
        )

        self.rate_limiter = RateLimiter(self.settings, self.redis_client)

        # TODO: Move this to config # pylint: disable=fixme
        with open(
            self.settings.static.sorry_too_busy_page_head, "r", encoding="utf-8"
        ) as too_busy_file:
            self.too_busy_page_template_head = too_busy_file.read()

        with open(
            self.settings.static.sorry_too_busy_page_tail, "r", encoding="utf-8"
        ) as too_busy_file:
            self.too_busy_page_template_tail = too_busy_file.read()

        with open(
            self.settings.static.outage_page_head, "r", encoding="utf-8"
        ) as outage_file:
            self.outage_page_template_head = outage_file.read()

        with open(
            self.settings.static.outage_page_tail, "r", encoding="utf-8"
        ) as outage_file:
            self.outage_page_template_tail = outage_file.read()

        with open(
            self.settings.static.disabled_mchtgn_page_head, "r", encoding="utf-8"
        ) as auth_proxy_disable:
            self.auth_by_proxy_head = auth_proxy_disable.read()

        with open(
            self.settings.static.disabled_mchtgn_page_tail, "r", encoding="utf-8"
        ) as auth_proxy_disable:
            self.auth_by_proxy_tail = auth_proxy_disable.read()

        with open(
            self.settings.oidc.clients_file, "r", encoding="utf-8"
        ) as clients_file:
            self.audience = list(json.loads(clients_file.read()).keys())

    def _is_outage(self):
        if hasattr(self.settings.ratelimit, "outage_key"):
            outage = self.redis_client.get(self.settings.ratelimit.outage_key)
            if outage:
                outage = outage.decode()
            else:
                return False

            if outage.lower() == "true" or outage == "1":
                return True

        return False

    @property
    def allowed_scopes(self):
        if hasattr(self.settings, "allowed_scopes"):
            return self.settings.allowed_scopes
        return ["openid"]

    def _post_login(
        self, login_digid_req: LoginDigiDRequest, id_provider: IdProvider
    ) -> Response:
        """
        Not all identity providers allow the HTTP-Redirect for performing authentication requests,
        For those that require HTTP-POST, this method is created. It generates an auto-submit form
        with the authentication request.

        Further if the system is configured to be in mocking mode, the auto-submit form is configured
        to use the mocking paths available.
        """
        force_digid = (
            login_digid_req.force_digid
            if login_digid_req.force_digid is not None
            else False
        )
        randstate = login_digid_req.state

        if self.settings.mock_digid.lower() == "true" and not force_digid:
            ##
            # Coming from /authorize in mocking mode we should always get in this fall into this branch
            # in which case login_digid_req only contains the randstate.
            ##
            base64_authn_request = base64.urlsafe_b64encode(
                json.dumps(login_digid_req.authorize_request.dict()).encode()
            ).decode()
            sso_url = f"/digid-mock?state={randstate}&idp_name={id_provider.name}&authorize_request={base64_authn_request}"

            authn_request = id_provider.create_authn_request([], [])
            return SAMLAuthNAutoSubmitResponse(
                sso_url=sso_url,
                relay_state=randstate,
                authn_request=authn_request,
                settings=self.settings,
            )

        if id_provider.authn_binding.endswith("POST"):
            try:
                authn_request = id_provider.create_authn_request(
                    login_digid_req.authorize_request.authorization_by_proxy
                )
            except ScopingAttributesNotAllowed as scoping_not_allowed:
                raise AuthorizationByProxyDisabled() from scoping_not_allowed

            return SAMLAuthNAutoSubmitResponse(
                sso_url=authn_request.sso_url,
                relay_state=randstate,
                authn_request=authn_request,
                settings=self.settings,
            )

        if id_provider.authn_binding.endswith("Redirect"):
            if login_digid_req.authorize_request is None:
                raise ValueError("AuthnRequest is None, which should not be possible")

            if login_digid_req.authorize_request.authorization_by_proxy:
                self.log.warning(
                    "User attempted to login using authorization by proxy. But is not supported for this IDProvider: %s",
                    id_provider.name,
                )
                raise AuthorizationByProxyDisabled()

            req = self._prepare_req(login_digid_req.authorize_request, id_provider.name)
            auth = OneLogin_Saml2_Auth(req, custom_base_path=id_provider.base_dir)
            return RedirectResponse(
                auth.login(
                    return_to=login_digid_req.state,
                    force_authn=False,
                    set_nameid_policy=False,
                )
            )

        raise UnexpectedAuthnBinding(
            f"Unknown Authn binding {id_provider.authn_binding} configured in idp metadata: {id_provider.name}"
        )

    def _prepare_req(self, auth_req: BaseModel, idp_name: str):
        """
        Prepare a authorization request to use the OneLogin SAML library.
        """
        return {
            "https": "on",
            "http_host": f"https://{idp_name}.{self.settings.saml.base_issuer}",
            "script_name": self.settings.authorize_endpoint,
            "get_data": auth_req.dict(),
        }

    def sorry_something_went_wrong(self, request: SorryPageRequest):
        """
        Endpoint serving the sorry to busy page. It includes a href button with error information
        in the query parameters.
        """
        allow_list = self.clients[request.client_id]["redirect_uris"]
        redirect_uri = _get_too_busy_redirect_error_uri(
            request.redirect_uri, request.state, allow_list
        )

        if request.reason in [
            constants.SomethingWrongReason.TOO_BUSY.value,
            constants.SomethingWrongReason.TOO_MANY_REQUEST.value,
        ]:
            return SomethingWrongHTMLResponse(
                redirect_uri,
                self.too_busy_page_template_head,
                self.too_busy_page_template_tail,
            )

        if (
            request.reason
            == constants.SomethingWrongReason.AUTH_BY_PROXY_DISABLED.value
        ):
            return SomethingWrongHTMLResponse(
                redirect_uri,
                self.auth_by_proxy_head,
                self.auth_by_proxy_tail,
            )

        if not self._is_outage:
            self.log.warning(
                "Someone landed on the outage page, but there is no outage."
            )

        # If we got to the sorry page, by default we have an outage
        return SomethingWrongHTMLResponse(
            redirect_uri,
            self.outage_page_template_head,
            self.outage_page_template_tail,
        )

    def _get_primary_idp(self, ip_address: str):
        if self._is_outage():
            raise DependentServiceOutage(self.settings.ratelimit.outage_key)

        primary_idp = self.redis_client.get(self.settings.primary_idp_key)
        if primary_idp:
            primary_idp = primary_idp.decode()
        else:
            raise ExpectedRedisValue(
                f"Expected {self.settings.primary_idp_key} key to be set in cache. Please check the primary_idp_key setting"
            )

        if (
            hasattr(self.settings, "mock_digid")
            and self.settings.mock_digid.lower() != "true"
        ):
            primary_idp = self.rate_limiter.rate_limit_test(ip_address)

        return primary_idp

    def authorize_endpoint(
        self, authorize_request: AuthorizeRequest, headers: Headers, ip_address: str
    ) -> Response:
        """
        Handles requests made to the authorize endpoint. It requires an Identity Provider (IDP) to be defined in the redis store under the
        key defined in the primary_idp_key setting. Further, ratelimiting is applied and, if the limit for the primary
        idp has been reached, the secundary or 'overflow_idp' is used if the ratelimiter allows it.

        Finally, the request is parsed and processed checking the query parameters against the client registration. If all is
        valid, a Redirect response or auto-submit POST response is returned depending on the active IDP and its corresponding configuration.
        """
        validate_auth_req(authorize_request, self.clients)
        primary_idp = self._get_primary_idp(ip_address)

        try:
            auth_req = self.oidc.parse_authentication_request(
                urlencode(authorize_request.dict()), headers
            )
        except InvalidAuthenticationRequest as invalid_auth_req:
            self.log.debug("received invalid authn request", exc_info=True)
            error_url = invalid_auth_req.to_error_url()
            if error_url:
                return RedirectResponse(error_url, status_code=303)

            raise AuthorizeEndpointException(
                error="invalid_request_object",
                error_description=f"Something went wrong: {str(invalid_auth_req)}",
            ) from invalid_auth_req

        except Exception as exception:  # pylint: disable=broad-except
            self.log.error("Handling error: %s", exception)
            self.log.error("Some unhandled error appeard", exc_info=True)

            raise AuthorizeEndpointException(
                error="request_not_supported",
                error_description="Some unhandled error in the rate limit tester. Unclear what went wrong",
            ) from exception

        randstate = self.redis_cache.gen_token()
        cache_auth_req(
            self.redis_cache, randstate, auth_req, authorize_request, primary_idp
        )

        # There is some special behavior defined on the auth_req when mocking. If we want identical
        # behavior through mocking with primary_idp=digid as without mocking, we need to
        # create a mock redirectresponse.
        id_provider = self.get_id_provider(primary_idp)
        return self._post_login(
            LoginDigiDRequest(state=randstate, authorize_request=authorize_request),
            id_provider=id_provider,
        )

    def token_endpoint(self, body: bytes, headers: Headers) -> JWTResponse:
        """
        This method handles the accesstoken endpoint. After the client has obtained an authorization code, by
        letting the resource owner login to the third party Identity Provider, this method processes the clients
        final request for a token.

        The request is handled by validating the urlencoded parameters in the body. Which include: grant_type, code,
        redirect_uri, client_id and code_verifier. If all is valid, the artifact is resolved from the IDP by sending
        an ArtifactResolve request and parsing its response. The response, containing the BSN, is encrypted and cached
        in the redis store under the hash of the token it is returning as a final step of this function.

        Validation of the accesstoken request includes:
            - checking the client_id
            - checking the redirect_uri configured for the client_id
            - checking whether the provided code is known in the redis store
            - checking whether the grant_type is as expected
            - validating the code_verifier against the received code_challenge and code_challenge_method during the
              authorize request.
        """
        code = parse_qs(body.decode())["code"][0]

        try:
            cached_artifact = hget_from_redis(
                self.redis_cache, code, constants.RedisKeys.ARTI.value
            )
            artifact = cached_artifact["artifact"]
            id_provider = cached_artifact["id_provider"]
            authorization_by_proxy = cached_artifact["authorization_by_proxy"]

            token_response = accesstoken(self.oidc, body, headers)
            try:
                encrypted_bsn = self._resolve_artifact(
                    artifact, id_provider, authorization_by_proxy
                )
            except UserNotAuthenticated as user_not_authenticated:
                # FastAPI middleware handles, no need to reraise - pylint: disable=raise-missing-from
                raise JWTError(
                    error=user_not_authenticated.oauth_error,
                    error_description=str(user_not_authenticated),
                )
            except ValueError:
                # FastAPI middleware handles, no need to reraise - pylint: disable=raise-missing-from
                raise JWTError(
                    error="server_error",
                    error_description="Attribute expected, but was not found",
                )

            access_key = create_redis_bsn_key(
                self.key, token_response.id_token.encode(), self.audience
            )

            self.redis_cache.set(access_key, encrypted_bsn)

            self.log.info(
                " User has returned from %s and we received a response (Mocking mode is %s)",
                id_provider.upper(),
                self.settings.mock_digid.upper(),
            )

            return token_response
        except UserNotAuthenticated as user_not_authenticated:
            self.log.debug(
                "invalid client authentication at token endpoint", exc_info=True
            )
            error_resp = TokenSAMLErrorResponse(
                error=user_not_authenticated.oauth_error,
                error_description=str(user_not_authenticated),
            ).to_dict()
        except InvalidClientAuthentication as invalid_client_auth:
            self.log.debug(
                "invalid client authentication at token endpoint", exc_info=True
            )
            error_resp = TokenErrorResponse(
                error="invalid_client", error_description=str(invalid_client_auth)
            ).to_dict()
        except OAuthError as oauth_error:
            self.log.debug("invalid request: %s", str(oauth_error), exc_info=True)
            error_resp = TokenErrorResponse(
                error=oauth_error.oauth_error, error_description=str(oauth_error)
            ).to_dict()
        except ExpiredResourceError as expired_err:
            self.log.debug("invalid request: %s", str(expired_err), exc_info=True)
            error_resp = TokenErrorResponse(
                error="invalid_request", error_description=str(expired_err)
            ).to_dict()

        # Error has occurred
        raise JWTError(**error_resp)

    def assertion_consumer_service(
        self, request: Request
    ) -> Union[RedirectResponse, HTMLResponse]:
        """
        This callback function handles the redirects retrieved from the active IDP, once the resource owner
        has logged into the active IDP, the IDP redirects the user to this endpoint with the provided artifact.
        This artifact is stored, and the user is redirected to the configured redirect_uri. The retrieved artifact
        is later used to verify the login, and retrieve the BSN.
        """
        state = request.query_params.get("RelayState", None)
        artifact = request.query_params.get("SAMLart", None)

        if state is None or artifact is None:
            return HTMLResponse(status_code=401, content="User not authorized")

        artifact_hashed = nacl.hash.sha256(artifact.encode()).decode()
        if (
            "mocking" in request.query_params
            and hasattr(self.settings, "mock_digid")
            and self.settings.mock_digid.lower() == "true"
        ):
            self.redis_cache.set("DIGID_MOCK" + artifact, "true")

        try:
            auth_req_dict = hget_from_redis(
                self.redis_cache, state, constants.RedisKeys.AUTH_REQ.value
            )
            auth_req = auth_req_dict[constants.RedisKeys.AUTH_REQ.value]
        except ExpiredResourceError as expired_err:
            self.log.error(
                "received invalid authn request for artifact %s. Reason: %s",
                artifact_hashed,
                expired_err,
                exc_info=True,
            )
            return HTMLResponse(
                status_code=404, content="Session expired, user not authorized"
            )

        authn_response = self.oidc.authorize(auth_req, "test_client")
        response_url = authn_response.request(auth_req["redirect_uri"], False)
        code = authn_response["code"]

        self.log.debug(
            "Storing sha256(artifact) %s under code %s", artifact_hashed, code
        )
        cache_artifact(
            self.redis_cache,
            code,
            artifact,
            auth_req_dict["id_provider"],
            auth_req_dict["authorization_by_proxy"],
        )

        cache_code_challenge(
            self.redis_cache,
            code,
            auth_req_dict["code_challenge"],
            auth_req_dict["code_challenge_method"],
        )
        self.log.debug("Stored code challenge")

        parsed_url = urlparse(response_url)
        r_url_query_params = parse_qs(parsed_url.query)

        if len(r_url_query_params) < 2:
            self.log.warning(
                "Query parameter is empty or contains empty values. Query params: %s",
                r_url_query_params,
            )

        return MetaRedirectResponse(redirect_url=response_url)

    def _resolve_artifact(
        self,
        artifact: str,
        id_provider_name: str,
        authorization_by_proxy: bool,
    ) -> Union[Dict[str, Any], bytes]:
        """
        given the the artifact and active IDP name, perform an artifact resolve request to the
        active Identity Provider. Retrieve the BSN and perform symmetric encryption to store it
        in the redis store.
        """
        hashed_artifact = nacl.hash.sha256(artifact.encode()).decode()
        self.log.debug(
            "Making and sending request sha256(artifact) %s", hashed_artifact
        )

        is_digid_mock = self.redis_cache.get("DIGID_MOCK" + artifact)
        if (
            hasattr(self.settings, "mock_digid")
            and self.settings.mock_digid.lower() == "true"
            and is_digid_mock is not None
        ):
            return {
                "type": constants.BSNStorage.RECRYPTED.value,
                "result": {
                    "bsn": self.bsn_encrypt.symm_encrypt(
                        {
                            "bsn": artifact,
                            "authorization_by_proxy": authorization_by_proxy,
                        }
                    )
                },
            }

        id_provider: IdProvider = self.get_id_provider(id_provider_name)
        resolved_artifact = _perform_artifact_resolve_request(artifact, id_provider)

        self.log.debug(
            "Received a response for sha256(artifact) %s with status_code %s",
            hashed_artifact,
            resolved_artifact.status_code,
        )
        artifact_response = ArtifactResponse.from_string(
            self.settings, resolved_artifact.text, id_provider
        )
        self.log.debug(
            "ArtifactResponse for %s, received status_code %s",
            hashed_artifact,
            artifact_response._saml_status_code,  # pylint: disable=protected-access
        )
        artifact_response.raise_for_status()
        self.log.debug("Validated sha256(artifact) %s", hashed_artifact)

        if id_provider.sp_metadata.cluster_settings is None:
            # We are able to decrypt the message, and we will
            bsn = _get_bsn_from_art_resp(
                artifact_response.get_bsn(authorization_by_proxy), id_provider
            )
            encrypted_bsn = self.bsn_encrypt.symm_encrypt(
                {"bsn": bsn, "authorization_by_proxy": authorization_by_proxy}
            )

            return {
                "type": constants.BSNStorage.RECRYPTED.value,
                "result": {"bsn": encrypted_bsn},
            }

        # Encryption done by another party, gather relevant info
        return {
            "type": constants.BSNStorage.CLUSTERED.value,
            "result": {
                "msg": base64.b64encode(artifact_response.to_string()),
                "msg_id": artifact_response.root.attrib["ID"],
            },
        }

    def bsn_attribute(
        self, request: Request, version: constants.Version = constants.Version.V2
    ) -> Response:
        """
        Handles the BSN claim on the accesstoken. Allows to retrieve a bsn
        corresponding to a valid token.
        """
        _, at_hash = is_authorized(self.key, request, self.audience)

        redis_bsn_key = at_hash
        bsn_dict = self.redis_cache.get(redis_bsn_key)

        if bsn_dict is None:
            raise HTTPException(
                status_code=408,
                detail="Resource expired.Try again after /authorize",
            )

        if bsn_dict["type"] == constants.BSNStorage.CLUSTERED.value:
            # We never decrypted the message, we cannot re-encrypt.
            return JSONResponse(
                content=bsn_dict["result"],
                status_code=200,
            )

        bsn = bsn_dict["result"]["bsn"]

        if version == constants.Version.V1:
            # Backwards compatibility with Inge4
            encrypted_bsn = self.bsn_encrypt.from_symm_to_pub(bsn, version=version)
            return Response(content=encrypted_bsn, status_code=200)

        encrypted_bsn = self.bsn_encrypt.from_symm_to_jwt(bsn)
        return Response(content=encrypted_bsn, status_code=200)

    def metadata(self, id_provider_name: str) -> Response:
        """
        Endpoint retrieving metadata for the specified identity providers if configured properly.
        """
        try:
            id_provider = self.get_id_provider(id_provider_name)
        except ValueError as val_err:
            raise HTTPException(status_code=404, detail="Page not found") from val_err

        errors = id_provider.sp_metadata.validate()
        if len(errors) == 0:
            return Response(
                content=id_provider.sp_metadata.get_xml().decode(),
                media_type="application/xml",
            )

        raise HTTPException(status_code=500, detail=", ".join(errors))
