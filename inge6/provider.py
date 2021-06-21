import base64
import json
import logging

from urllib.parse import parse_qs, urlencode
from typing import Optional, Text
from datetime import datetime

import requests

import nacl.hash
from starlette.datastructures import Headers

from fastapi import FastAPI, Request, Response, HTTPException
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

from .config import settings
from .cache import get_redis_client, redis_cache
from .utils import create_post_autosubmit_form, create_page_too_busy
from .encrypt import Encrypt
from .models import AuthorizeRequest
from .exceptions import TooBusyError, TokenSAMLErrorResponse, TooManyRequestsFromOrigin

from .saml.exceptions import UserNotAuthenticated
from .saml.provider import Provider as SAMLProvider
from .saml import (
    AuthNRequest, ArtifactResolveRequest, ArtifactResponse
)

from .oidc.provider import Provider as OIDCProvider
from .oidc.authorize import (
    is_authorized,
    validate_jwt_token,
    accesstoken,
)

_PROVIDER = None

def _create_authn_post_context(relay_state: str, url: str, issuer_id) -> dict:
    saml_request = AuthNRequest(url, issuer_id)
    return {
        'sso_url': url,
        'saml_request': saml_request.get_base64_string().decode(),
        'relay_state': relay_state
    }

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

def _create_redis_bsn_key(key: str, id_token: str) -> str:
    jwt = validate_jwt_token(key, id_token)
    return jwt['at_hash']

def _rate_limit_test(ip_address: str, user_limit_key: str, ip_expire_s: int) -> None:
    """
    Test is we have passed the user limit defined in the redis-store. The rate limit
    defines the number of users per second which we allow.

    if no user_limit is found in the redis store, this check is treated as 'disabled'.

    :param user_limit_key: the key in the redis store that defines the number of allowed users per 10th of a second
    :raises: TooBusyError when the number of users exceeds the allowed number.
    """
    ip_hash = nacl.hash.sha256(ip_address.encode()).decode()
    ip_key = "tvs:ipv4:" + ip_hash
    if get_redis_client().get(ip_key) is not None:
        raise TooManyRequestsFromOrigin(f"Too many requests from the same ip_address during the last {ip_expire_s} seconds.")

    get_redis_client().set(ip_key, "exists", ex=ip_expire_s)

    user_limit = get_redis_client().get(user_limit_key)

    if user_limit is None:
        return

    user_limit = int(user_limit)
    timeslot = int(datetime.utcnow().timestamp() * 10)

    timeslot_key = "tvs:limiter:" + str(timeslot)
    num_users = get_redis_client().incr(timeslot_key)

    if num_users == 1:
        get_redis_client().expire(timeslot_key, 2)
    elif num_users >= user_limit:
        raise TooBusyError("Servers are too busy at this point, please try again later")


def _get_too_busy_redirect_error_uri(redirect_uri, state):
    """
    Given the redirect uri and state, return an error to the client desribing the service
    is too busy to handle an authorize request.

        redirect_uri?error=login_required&error_description=The+servers+are+too+busy+right+now,+please+try+again+later&state=34Gf3431D

    :param redirect_uri: uri to pass the error query params to
    :param state: state that corresponds to the request

    """
    error = "login_required"
    error_desc = "The servers are too busy right now, please try again later."
    return redirect_uri + f"?error={error}&error_description={error_desc}&state={state}"

class Provider(OIDCProvider, SAMLProvider):
    BSN_SIGN_KEY = settings.bsn.sign_key
    BSN_ENCRYPT_KEY = settings.bsn.encrypt_key
    BSN_LOCAL_SYMM_KEY = settings.bsn.local_symm_key

    def __init__(self, app: FastAPI) -> None:
        OIDCProvider.__init__(self, app)
        SAMLProvider.__init__(self)

        self.bsn_encrypt = Encrypt(
            raw_sign_key=self.BSN_SIGN_KEY,
            raw_enc_key=self.BSN_ENCRYPT_KEY,
            raw_local_enc_key=self.BSN_LOCAL_SYMM_KEY
        )

        with open(settings.ratelimit.sorry_too_busy_page, 'r') as too_busy_file:
            self.too_busy_page_template = too_busy_file.read()

    def authorize_endpoint(self, authorize_request: AuthorizeRequest, headers: Headers, ip_address: str) -> Response:
        try:
            _rate_limit_test(ip_address, settings.ratelimit.user_limit_key, int(settings.ratelimit.ip_expire_in_s))
        except (TooBusyError, TooManyRequestsFromOrigin) as rate_limit_error:
            logging.getLogger().warning("Rate-limit: Service denied someone access, cancelling authorization flow. Reason: %s", str(rate_limit_error))
            redirect_uri = _get_too_busy_redirect_error_uri(authorize_request.redirect_uri, authorize_request.state)
            too_busy_page = create_page_too_busy(self.too_busy_page_template, redirect_uri)
            return HTMLResponse(content=too_busy_page)

        try:
            auth_req = self.parse_authentication_request(urlencode(authorize_request.dict()), headers)
        except InvalidAuthenticationRequest as invalid_auth_req:
            logging.getLogger().debug('received invalid authn request', exc_info=True)
            error_url = invalid_auth_req.to_error_url()
            if error_url:
                return RedirectResponse(error_url, status_code=303)

            return Response(content='Something went wrong: {}'.format(str(invalid_auth_req)), status_code=400)

        randstate = redis_cache.gen_token()
        _cache_auth_req(randstate, auth_req, authorize_request)
        return HTMLResponse(content=self._login(randstate))

    def token_endpoint(self, body: bytes, headers: Headers) -> JSONResponse:
        code = parse_qs(body.decode())['code'][0]
        artifact = redis_cache.hget(code, 'arti')

        try:
            token_response = accesstoken(self, body, headers)
            encrypted_bsn = self._resolve_artifact(artifact)

            access_key = _create_redis_bsn_key(self.key, token_response['id_token'].encode())
            redis_cache.set(access_key, encrypted_bsn)

            json_content_resp = jsonable_encoder(token_response.to_dict())
            return JSONResponse(content=json_content_resp)
        except UserNotAuthenticated as user_not_authenticated:
            logging.getLogger().debug('invalid client authentication at token endpoint', exc_info=True)
            error_resp = TokenSAMLErrorResponse(error=user_not_authenticated.oauth_error, error_description=str(user_not_authenticated)).to_json()
        except InvalidClientAuthentication as invalid_client_auth:
            logging.getLogger().debug('invalid client authentication at token endpoint', exc_info=True)
            error_resp = TokenErrorResponse(error='invalid_client', error_description=str(invalid_client_auth)).to_json()
        except OAuthError as oauth_error:
            logging.getLogger().debug('invalid request: %s', str(oauth_error), exc_info=True)
            error_resp = TokenErrorResponse(error=oauth_error.oauth_error, error_description=str(oauth_error)).to_json()

        # Error has occurred
        response = JSONResponse(jsonable_encoder(error_resp), status_code=400)
        return response

    def _login(self, randstate: str, force_digid: Optional[bool] = False) -> Text:
        issuer_id = self.sp_metadata.issuer_id
        if settings.mock_digid.lower() == "true" and not force_digid:
            authn_post_ctx = _create_authn_post_context(relay_state=randstate, url=f'/digid-mock?state={randstate}', issuer_id=issuer_id)
        else:
            sso_url = self.idp_metadata.get_sso()['location']
            authn_post_ctx = _create_authn_post_context(relay_state=randstate, url=sso_url, issuer_id=issuer_id)

        return create_post_autosubmit_form(authn_post_ctx)

    def assertion_consumer_service(self, request: Request) -> RedirectResponse:
        state = request.query_params['RelayState']
        artifact = request.query_params['SAMLart']

        if 'mocking' in request.query_params:
            redis_cache.set('DIGID_MOCK' + artifact, 'true')

        auth_req_dict = redis_cache.hget(state, 'auth_req')
        auth_req = auth_req_dict['auth_req']

        authn_response = self.authorize(auth_req, 'test_client')
        response_url = authn_response.request(auth_req['redirect_uri'], False)
        code = authn_response['code']

        redis_cache.hset(code, 'arti', artifact)
        _store_code_challenge(code, auth_req_dict['code_challenge'], auth_req_dict['code_challenge_method'])
        return RedirectResponse(response_url, status_code=303)

    def _resolve_artifact(self, artifact: str) -> bytes:
        is_digid_mock = redis_cache.get('DIGID_MOCK' + artifact)
        if settings.mock_digid.lower() == "true" and is_digid_mock is not None:
            return self.bsn_encrypt.symm_encrypt(artifact)

        sso_url = self.idp_metadata.get_sso()['location']
        issuer_id = self.sp_metadata.issuer_id
        resolve_artifact_req = ArtifactResolveRequest(artifact, sso_url, issuer_id).get_xml()
        url = self.idp_metadata.get_artifact_rs()['location']
        headers = {
            'SOAPAction' : '"https://artifact-pp2.toegang.overheid.nl/kvs/rd/resolve_artifact"',
            'content-type': 'text/xml'
        }
        resolved_artifact = requests.post(url, headers=headers, data=resolve_artifact_req, cert=('saml/certs/sp.crt', 'saml/certs/sp.key'))
        artifact_response = ArtifactResponse.from_string(resolved_artifact.text, self)
        artifact_response.raise_for_status()

        bsn = artifact_response.get_bsn()
        encrypted_bsn = self.bsn_encrypt.symm_encrypt(bsn)
        return encrypted_bsn

    def bsn_attribute(self, request: Request) -> Response:
        _, at_hash= is_authorized(self.key, request)

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

def get_provider(app: FastAPI = None) -> Provider:
    global _PROVIDER # pylint: disable=global-statement
    if _PROVIDER is None:
        if app is None:
            raise Exception("app cannot be None on first call.")
        _PROVIDER = Provider(app)
    return _PROVIDER
