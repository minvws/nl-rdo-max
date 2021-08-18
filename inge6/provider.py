import base64
import json
import logging
from logging import Logger

from urllib import parse

from urllib.parse import parse_qs, urlencode
from typing import Text, List, Union
from datetime import datetime

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

from .config import settings
from .cache import get_redis_client, redis_cache
from .utils import create_post_autosubmit_form, create_page_too_busy, create_acs_redirect_link, create_authn_post_context
from .encrypt import Encrypt
from .models import AuthorizeRequest, LoginDigiDRequest, SorryPageRequest
from .exceptions import (
    TooBusyError, TokenSAMLErrorResponse, TooManyRequestsFromOrigin,
    ExpiredResourceError
)
from .constants import SECTOR_CODES

from .saml.exceptions import UserNotAuthenticated
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

def _cache_auth_req(randstate: str, auth_req: OICAuthRequest, authorization_request: AuthorizeRequest) -> None:
    value = {
        'auth_req': auth_req,
        'code_challenge': authorization_request.code_challenge,
        'code_challenge_method': authorization_request.code_challenge_method
    }
    redis_cache.hset(randstate, 'auth_req', value)

def _store_code_challenge(code: str, code_challenge: str, code_challenge_method: str) -> None:
    value = {
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method
    }
    redis_cache.hset(code, 'cc_cm', value)

def hget_from_redis(namespace, key):
    result = redis_cache.hget(namespace, key)
    if result is None:
        raise ExpiredResourceError("Resource is not (any longer) available in redis")
    return result

def _create_redis_bsn_key(key: str, id_token: str, audience: List[Text]) -> str:
    jwt = validate_jwt_token(key, id_token, audience)
    return jwt['at_hash']

def _rate_limit_test(ip_address: str, user_limit_key: str, ip_expire_s: int) -> None:
    """
    Test is we have passed the user limit defined in the redis-store. The rate limit
    defines the number of users per second which we allow.

    if no user_limit is found in the redis store, this check is treated as 'disabled'.

    :param user_limit_key: the key in the redis store that defines the number of allowed users per 10th of a second
    :raises: TooBusyError when the number of users exceeds the allowed number.
    """
    ip_key = "tvs:ipv4:" + ip_address
    ip_key_exists = get_redis_client().incr(ip_key)
    if ip_key_exists != 1:
        raise TooManyRequestsFromOrigin(f"Too many requests from the same ip_address during the last {ip_expire_s} seconds.")
    get_redis_client().expire(ip_key, ip_expire_s)

    user_limit = get_redis_client().get(user_limit_key)

    if user_limit is None:
        return

    user_limit = int(user_limit)
    timeslot = int(datetime.utcnow().timestamp())

    timeslot_key = "tvs:limiter:" + str(timeslot)
    num_users = get_redis_client().incr(timeslot_key)

    if num_users == 1:
        get_redis_client().expire(timeslot_key, 2)
    elif num_users >= user_limit:
        raise TooBusyError("Servers are too busy at this point, please try again later")

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
    return {
        'https': 'on',
        'http_host': settings.issuer,
        'script_name': settings.authorize_endpoint,
        'get_date': auth_req.dict(),
        'post_data': None
    }

def _get_bsn_from_art_resp(bsn_response: str) -> str:
    if settings.connect_to_idp.lower() == 'tvs':
        return bsn_response

    if settings.connect_to_idp.lower() == 'digid':
        sector_split = bsn_response.split(':')
        sector_number = SECTOR_CODES[sector_split[0]]
        if sector_number != 'BSN':
            raise ValueError("Expected BSN number, received: {}".format(sector_number))
        return sector_split[1]

    raise ValueError("Invalid value for connect_to_idp: {}".format(settings.connect_to_idp))

class Provider(OIDCProvider, SAMLProvider):
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
            if settings.mock_digid.lower() != 'true':
                _rate_limit_test(ip_address, settings.ratelimit.user_limit_key, int(settings.ratelimit.ip_expire_in_s))
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
        _cache_auth_req(randstate, auth_req, authorize_request)

        # There is some special behavior defined on the auth_req when mocking. If we want identical
        # behavior through mocking with connect_to_idp=digid as without mocking, we need to
        # create a mock redirectresponse.
        if settings.connect_to_idp.lower() == 'tvs'or settings.mock_digid.lower() == 'true':
            return HTMLResponse(content=self._login(LoginDigiDRequest(state=randstate)))

        req = _prepare_req(authorize_request)
        auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.saml.base_dir)
        return RedirectResponse(auth.login())

    def token_endpoint(self, body: bytes, headers: Headers) -> JSONResponse:
        code = parse_qs(body.decode())['code'][0]

        try:
            artifact = hget_from_redis(code, 'arti')
            token_response = accesstoken(self, body, headers)
            encrypted_bsn = self._resolve_artifact(artifact)

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

    def _login(self, login_digid_req: LoginDigiDRequest) -> Text:
        force_digid = login_digid_req.force_digid if login_digid_req.force_digid is not None else False
        randstate = login_digid_req.state

        issuer_id = self.sp_metadata.issuer_id

        if settings.mock_digid.lower() == "true" and not force_digid:
            authn_post_ctx = create_authn_post_context(relay_state=randstate, url=f'/digid-mock?state={randstate}', issuer_id=issuer_id)
        else:
            sso_url = self.idp_metadata.get_sso()['location']
            authn_post_ctx = create_authn_post_context(relay_state=randstate, url=sso_url, issuer_id=issuer_id)

        return create_post_autosubmit_form(authn_post_ctx)

    def assertion_consumer_service(self, request: Request) -> Union[RedirectResponse, HTMLResponse]:
        state = request.query_params['RelayState']
        artifact = request.query_params['SAMLart']
        artifact_hashed =  nacl.hash.sha256(artifact.encode()).decode()

        if 'mocking' in request.query_params and settings.mock_digid.lower() == 'true':
            redis_cache.set('DIGID_MOCK' + artifact, 'true')

        try:
            auth_req_dict = hget_from_redis(state, 'auth_req')
            auth_req = auth_req_dict['auth_req']
        except ExpiredResourceError as expired_err:
            log.error('received invalid authn request for artifact %s. Reason: %s', artifact_hashed, expired_err, exc_info=True)
            return HTMLResponse('Session expired')

        authn_response = self.authorize(auth_req, 'test_client')
        response_url = authn_response.request(auth_req['redirect_uri'], False)
        code = authn_response['code']

        log.debug('Storing sha256(artifact) %s under code %s', artifact_hashed, code)
        redis_cache.hset(code, 'arti', artifact)
        _store_code_challenge(code, auth_req_dict['code_challenge'], auth_req_dict['code_challenge_method'])
        log.debug('Stored code challenge')

        return HTMLResponse(create_acs_redirect_link({"redirect_url": response_url}))

    def _resolve_artifact(self, artifact: str) -> bytes:
        hashed_artifact = nacl.hash.sha256(artifact.encode()).decode()
        log.debug('Making and sending request sha256(artifact) %s', hashed_artifact)

        is_digid_mock = redis_cache.get('DIGID_MOCK' + artifact)
        if settings.mock_digid.lower() == "true" and is_digid_mock is not None:
            return self.bsn_encrypt.symm_encrypt(artifact)

        sso_url = self.idp_metadata.get_sso()['location']
        issuer_id = self.sp_metadata.issuer_id
        resolve_artifact_req = ArtifactResolveRequest(artifact, sso_url, issuer_id).get_xml()
        url = self.idp_metadata.get_artifact_rs()['location']
        headers = {
            'SOAPAction' : 'resolve_artifact',
            'content-type': 'text/xml'
        }
        resolved_artifact = requests.post(url, headers=headers, data=resolve_artifact_req, cert=(settings.saml.cert_path, settings.saml.key_path))

        log.debug('Received a response for sha256(artifact) %s with status_code %s', hashed_artifact, resolved_artifact.status_code)
        artifact_response = ArtifactResponse.from_string(resolved_artifact.text, self)
        log.debug('ArtifactResponse for %s, received status_code %s', hashed_artifact, artifact_response._saml_status_code) # pylint: disable=protected-access
        artifact_response.raise_for_status()
        log.debug('Validated sha256(artifact) %s', hashed_artifact)

        bsn = _get_bsn_from_art_resp(artifact_response.get_bsn())
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

    def metadata(self) -> Response:
        errors = self.sp_metadata.validate()

        if len(errors) == 0:
            return Response(content=self.sp_metadata.get_xml().decode(), media_type="application/xml")

        raise HTTPException(status_code=500, detail=', '.join(errors))

def get_provider() -> Provider:
    global _PROVIDER # pylint: disable=global-statement
    if _PROVIDER is None:
        _PROVIDER = Provider()
    return _PROVIDER
