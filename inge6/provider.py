import base64

import json
import logging
from logging import Logger

from urllib import parse

from urllib.parse import parse_qs, urlencode
from typing import Text, List, Union

import requests

import nacl.hash

from starlette.datastructures import Headers

from fastapi import Request, Response, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.encoders import jsonable_encoder

from oic.oic.message import (
    AuthorizationRequest as OICAuthRequest,
    TokenErrorResponse
)
from pyop.exceptions import (
    InvalidAuthenticationRequest,
    InvalidClientAuthentication, OAuthError
)

from onelogin.saml2.auth import OneLogin_Saml2_Auth

from . import constants
from .config import settings
from .cache import get_redis_client, redis_cache
from .rate_limiter import rate_limit_test
from .utils import create_post_autosubmit_form, create_page_too_busy, create_acs_redirect_link, create_authn_post_context
from .encrypt import Encrypt
from .models import AuthorizeRequest, LoginDigiDRequest, SorryPageRequest
from .exceptions import (
    TooBusyError, TokenSAMLErrorResponse, TooManyRequestsFromOrigin,
    ExpiredResourceError
)

from .saml.exceptions import UserNotAuthenticated
from .saml.id_provider import IdProvider
from .saml.provider import Provider as SAMLProvider
from .saml import (
    ArtifactResolveRequest, ArtifactResponse
)

from .oidc.provider import Provider as OIDCProvider
from .oidc.authorize import (
    is_authorized,
    validate_jwt_token,
    accesstoken,
)

log: Logger = logging.getLogger(__package__)

_PROVIDER = None

def _cache_auth_req(randstate: str, auth_req: OICAuthRequest, authorization_request: AuthorizeRequest,
                    id_provider: str) -> None:
    """
    Method for assembling the data related to the auth request performed, including the code_challenge,
    code_challenge_method and the to be used identity provider. and storing it in the RedisStore under the
    constants.RedisKeys.AUTH_REQ enum. 
    """
    value = {
        'auth_req': auth_req,
        'code_challenge': authorization_request.code_challenge,
        'code_challenge_method': authorization_request.code_challenge_method,
        'id_provider': id_provider
    }

    redis_cache.hset(randstate, constants.RedisKeys.AUTH_REQ.value, value)

def _cache_code_challenge(code: str, code_challenge: str, code_challenge_method: str) -> None:
    """
    Method for assembling the data related to the upcoming accesstoken request, including the code, code_challenge
    and code_challenge_method. and storing it in the RedisStore under the constants.RedisKeys.CC_CM enum.
    """
    value = {
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method
    }
    redis_cache.hset(code, constants.RedisKeys.CC_CM.value, value)

def _cache_artifact(code: str, artifact: str, id_provider: str):
    """
    Method for assembling the data related to the upcoming accesstoken request, including the artifact and
    identity_provider that has been used to retrieve the artifact. These are stored in the RedisStore under the
    constants.RedisKeys.CC_CM enum.
    """
    value = {
        'artifact': artifact,
        'id_provider': id_provider
    }
    redis_cache.hset(code, constants.RedisKeys.ARTI.value, value)

def hget_from_redis(namespace, key):
    """
    Method to retrieve something from redis, and if no result is found, throw a resource has expired exception.
    """
    result = redis_cache.hget(namespace, key)
    if result is None:
        raise ExpiredResourceError("Resource is not (any longer) available in redis")
    return result

def _create_redis_bsn_key(key: str, id_token: str, audience: List[Text]) -> str:
    """
    Method retrieving the redis_bsn_key used to retrieve the bsn from redis. This is the hash of the id_token that has
    been provided as a response to the accesstoken request.
    """
    jwt = validate_jwt_token(key, id_token, audience)
    return jwt['at_hash']

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

def _prepare_req(auth_req: AuthorizeRequest):
    """
    Prepare a authorization request to use the OneLogin SAML library.
    """
    return {
        'https': 'on',
        'http_host': settings.issuer,
        'script_name': settings.authorize_endpoint,
        'get_date': auth_req.dict(),
        'post_data': None
    }

def _get_bsn_from_art_resp(bsn_response: str, saml_spec_version: float) -> str:
    """
    Depending on the saml versioning the bsn is or is not prepended with a sectore code.

    For saml specification 4.4 and 4.5 the bsn is encrypted, and not prepended with such codes.
    For saml specification 3.5 the bsn is prepended with a sector_code representing its value to
    be either a BSN number or SOFI number.
    """
    if saml_spec_version >= 4.4:
        return bsn_response

    if saml_spec_version == 3.5:
        sector_split = bsn_response.split(':')
        sector_number = constants.SECTOR_CODES[sector_split[0]]
        if sector_number != constants.SectorNumber.BSN:
            raise ValueError("Expected BSN number, received: {}".format(sector_number))
        return sector_split[1]

    raise ValueError("Unknown SAML specification, known: 3.5, >=4.4")


def _post_login(login_digid_req: LoginDigiDRequest, id_provider: IdProvider) -> Text:
    """
    Not all identity providers allow the HTTP-Redirect for performing authentication requests,
    For those that require HTTP-POST, this method is created. It generates an auto-submit form
    with the authentication request.

    Further if the system is configured to be in mocking mode, the auto-submit form is configured
    to use the mocking paths available.
    """
    force_digid = login_digid_req.force_digid if login_digid_req.force_digid is not None else False
    randstate = login_digid_req.state

    issuer_id = id_provider.sp_metadata.issuer_id

    if settings.mock_digid.lower() == "true" and not force_digid:
        authn_post_ctx = create_authn_post_context(
            relay_state=randstate,
            url=f'/digid-mock?state={randstate}',
            issuer_id=issuer_id,
            keypair=id_provider.keypair_paths
        )
    else:
        sso_url = id_provider.idp_metadata.get_sso()['location']
        authn_post_ctx = create_authn_post_context(
            relay_state=randstate,
            url=sso_url,
            issuer_id=issuer_id,
            keypair=id_provider.keypair_paths
        )

    return create_post_autosubmit_form(authn_post_ctx)

def _perform_artifact_resolve_request(artifact: str, id_provider: IdProvider):
    """
    Perform an artifact resolve request using the provided artifact and identity provider.
    The identity provider tells us the locations of the endpoints needed for resolving the artifact,
    and the artifact is needed for the provider to resolve the requested attribute.
    """
    sso_url = id_provider.idp_metadata.get_sso()['location']
    issuer_id = id_provider.sp_metadata.issuer_id
    url = id_provider.idp_metadata.get_artifact_rs()['location']

    resolve_artifact_req = ArtifactResolveRequest(artifact, sso_url, issuer_id, id_provider.keypair_paths)
    headers = {
        'SOAPAction' : 'resolve_artifact',
        'content-type': 'text/xml'
    }

    return requests.post(
        url,
        headers=headers,
        data=resolve_artifact_req.get_xml(),
        cert=(id_provider.cert_path, id_provider.key_path)
    )

class Provider(OIDCProvider, SAMLProvider):
    """
    This provider is the bridge between OIDC and SAML. It implements the OIDC protocol
    and connects to a configured SAML provider.
    """
    BSN_SIGN_KEY = settings.bsn.sign_key
    BSN_ENCRYPT_KEY = settings.bsn.encrypt_key
    BSN_LOCAL_SYMM_KEY = settings.bsn.local_symm_key

    def __init__(self) -> None:
        OIDCProvider.__init__(self)
        SAMLProvider.__init__(self)

        self.bsn_encrypt = Encrypt(
            raw_sign_key=self.BSN_SIGN_KEY,
            raw_enc_key=self.BSN_ENCRYPT_KEY,
            raw_local_enc_key=self.BSN_LOCAL_SYMM_KEY
        )

        with open(settings.ratelimit.sorry_too_busy_page_head, 'r') as too_busy_file:
            self.too_busy_page_template_head = too_busy_file.read()

        with open(settings.ratelimit.sorry_too_busy_page_tail, 'r') as too_busy_file:
            self.too_busy_page_template_tail = too_busy_file.read()

        with open(settings.oidc.clients_file, 'r') as clients_file:
            self.audience = list(json.loads(clients_file.read()).keys())

    def sorry_too_busy(self, request: SorryPageRequest):
        allow_list = self.clients[request.client_id]['redirect_uris']
        redirect_uri = _get_too_busy_redirect_error_uri(request.redirect_uri, request.state, allow_list)
        too_busy_page = create_page_too_busy(self.too_busy_page_template_head, self.too_busy_page_template_tail, redirect_uri)
        return HTMLResponse(content=too_busy_page)

    def authorize_endpoint(self, authorize_request: AuthorizeRequest, headers: Headers, ip_address: str) -> Response:
        try:
            connect_to_idp = get_redis_client().get(settings.connect_to_idp_key)
            if connect_to_idp:
                connect_to_idp = connect_to_idp.decode()
            else:
                raise KeyError("Expected connect_to_idp_key to be set in redis, but wasn't")

            if settings.mock_digid.lower() != 'true':
                connect_to_idp = rate_limit_test(ip_address)
        except (TooBusyError, TooManyRequestsFromOrigin) as rate_limit_error:
            log.warning("Rate-limit: Service denied someone access, cancelling authorization flow. Reason: %s", str(rate_limit_error))
            query_params = {
                'redirect_uri': authorize_request.redirect_uri,
                'client_id': authorize_request.client_id,
                'state': authorize_request.state
            }
            return RedirectResponse('/sorry-too-busy?' + parse.urlencode(query_params))

        try:
            auth_req = self.parse_authentication_request(urlencode(authorize_request.dict()), headers)
        except InvalidAuthenticationRequest as invalid_auth_req:
            log.debug('received invalid authn request', exc_info=True)
            error_url = invalid_auth_req.to_error_url()
            if error_url:
                return RedirectResponse(error_url, status_code=303)

            return Response(content='Something went wrong: {}'.format(str(invalid_auth_req)), status_code=400)

        randstate = redis_cache.gen_token()
        _cache_auth_req(randstate, auth_req, authorize_request, connect_to_idp)

        # There is some special behavior defined on the auth_req when mocking. If we want identical
        # behavior through mocking with connect_to_idp=digid as without mocking, we need to
        # create a mock redirectresponse.
        id_provider = self.get_id_provider(connect_to_idp)
        if id_provider.authn_binding.endswith('POST') or settings.mock_digid.lower() == 'true':
            return HTMLResponse(content=_post_login(
                LoginDigiDRequest(state=randstate),
                id_provider=id_provider
            ))

        req = _prepare_req(authorize_request)
        auth = OneLogin_Saml2_Auth(req, custom_base_path=id_provider.base_dir)
        return RedirectResponse(auth.login())

    def token_endpoint(self, body: bytes, headers: Headers) -> JSONResponse:
        code = parse_qs(body.decode())['code'][0]

        try:
            cached_artifact = hget_from_redis(code, constants.RedisKeys.ARTI)
            artifact = cached_artifact['artifact']
            id_provider = cached_artifact['id_provider']

            token_response = accesstoken(self, body, headers)
            encrypted_bsn = self._resolve_artifact(artifact, id_provider)

            access_key = _create_redis_bsn_key(self.key, token_response['id_token'].encode(), self.audience)
            redis_cache.set(access_key, encrypted_bsn)

            json_content_resp = jsonable_encoder(token_response.to_dict())
            return JSONResponse(content=json_content_resp)
        except UserNotAuthenticated as user_not_authenticated:
            log.debug('invalid client authentication at token endpoint', exc_info=True)
            error_resp = TokenSAMLErrorResponse(error=user_not_authenticated.oauth_error, error_description=str(user_not_authenticated)).to_json()
        except InvalidClientAuthentication as invalid_client_auth:
            log.debug('invalid client authentication at token endpoint', exc_info=True)
            error_resp = TokenErrorResponse(error='invalid_client', error_description=str(invalid_client_auth)).to_json()
        except OAuthError as oauth_error:
            log.debug('invalid request: %s', str(oauth_error), exc_info=True)
            error_resp = TokenErrorResponse(error=oauth_error.oauth_error, error_description=str(oauth_error)).to_json()
        except ExpiredResourceError as expired_err:
            log.debug('invalid request: %s', str(expired_err), exc_info=True)
            error_resp = TokenErrorResponse(error='invalid_request', error_description=str(expired_err)).to_json()

        # Error has occurred
        response = JSONResponse(jsonable_encoder(error_resp), status_code=400)
        return response

    def assertion_consumer_service(self, request: Request) -> Union[RedirectResponse, HTMLResponse]:
        state = request.query_params['RelayState']
        artifact = request.query_params['SAMLart']
        artifact_hashed =  nacl.hash.sha256(artifact.encode()).decode()

        if 'mocking' in request.query_params and settings.mock_digid.lower() == 'true':
            redis_cache.set('DIGID_MOCK' + artifact, 'true')

        try:
            auth_req_dict = hget_from_redis(state, constants.RedisKeys.AUTH_REQ.value)
            auth_req = auth_req_dict[constants.RedisKeys.AUTH_REQ.value]
        except ExpiredResourceError as expired_err:
            log.error('received invalid authn request for artifact %s. Reason: %s', artifact_hashed, expired_err, exc_info=True)
            return HTMLResponse('Session expired')

        authn_response = self.authorize(auth_req, 'test_client')
        response_url = authn_response.request(auth_req['redirect_uri'], False)
        code = authn_response['code']

        log.debug('Storing sha256(artifact) %s under code %s', artifact_hashed, code)
        _cache_artifact(code, artifact, auth_req_dict['id_provider'])

        _cache_code_challenge(code, auth_req_dict['code_challenge'], auth_req_dict['code_challenge_method'])
        log.debug('Stored code challenge')

        return HTMLResponse(create_acs_redirect_link({"redirect_url": response_url}))

    def _resolve_artifact(self, artifact: str, id_provider_name: str) -> bytes:
        hashed_artifact = nacl.hash.sha256(artifact.encode()).decode()
        log.debug('Making and sending request sha256(artifact) %s', hashed_artifact)

        is_digid_mock = redis_cache.get('DIGID_MOCK' + artifact)
        if settings.mock_digid.lower() == "true" and is_digid_mock is not None:
            return self.bsn_encrypt.symm_encrypt(artifact)

        id_provider: IdProvider = self.get_id_provider(id_provider_name)
        resolved_artifact = _perform_artifact_resolve_request(artifact, id_provider)

        log.debug('Received a response for sha256(artifact) %s with status_code %s', hashed_artifact, resolved_artifact.status_code)
        artifact_response = ArtifactResponse.from_string(resolved_artifact.text, id_provider)
        log.debug('ArtifactResponse for %s, received status_code %s', hashed_artifact, artifact_response._saml_status_code) # pylint: disable=protected-access
        artifact_response.raise_for_status()
        log.debug('Validated sha256(artifact) %s', hashed_artifact)

        bsn = _get_bsn_from_art_resp(artifact_response.get_bsn(), id_provider.saml_spec_version)
        encrypted_bsn = self.bsn_encrypt.symm_encrypt(bsn)
        return encrypted_bsn

    def bsn_attribute(self, request: Request) -> Response:
        _, at_hash= is_authorized(self.key, request, self.audience)

        redis_bsn_key = at_hash
        attributes = redis_cache.get(redis_bsn_key)

        if attributes is None:
            raise HTTPException(status_code=408, detail="Resource expired.Try again after /authorize", )

        decoded_json = base64.b64decode(attributes).decode()
        bsn_dict = json.loads(decoded_json)
        encrypted_bsn = self.bsn_encrypt.from_symm_to_pub(bsn_dict)
        return Response(content=encrypted_bsn, status_code=200)

    def metadata(self, id_provider_name: str) -> Response:
        try:
            id_provider = self.get_id_provider(id_provider_name)
        except ValueError as val_err:
            raise HTTPException(status_code=404, detail="Page not found") from val_err

        errors = id_provider.sp_metadata.validate()
        if len(errors) == 0:
            return Response(content=id_provider.sp_metadata.get_xml().decode(), media_type="application/xml")

        raise HTTPException(status_code=500, detail=', '.join(errors))

def get_provider() -> Provider:
    global _PROVIDER # pylint: disable=global-statement
    if _PROVIDER is None:
        _PROVIDER = Provider()
    return _PROVIDER
