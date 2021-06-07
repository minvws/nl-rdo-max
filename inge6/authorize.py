
import logging
import base64
from urllib.parse import urlencode, parse_qs
import nacl.hash

from fastapi import  Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.encoders import jsonable_encoder

from oic.oic.message import TokenErrorResponse, UserInfoErrorResponse
from pyop.access_token import AccessToken, BearerTokenError
from pyop.exceptions import (
    InvalidAuthenticationRequest, InvalidAccessToken,
    InvalidClientAuthentication, OAuthError
)

from . import tvs_access
from .models import AuthorizeRequest
from .oidc_provider import get_oidc_provider
from .cache import redis_cache
from .saml.exceptions import UserNotAuthenticated


def authorize(authorization_request: AuthorizeRequest, headers):
    try:
        auth_req = get_oidc_provider().parse_authentication_request(urlencode(authorization_request.dict()), headers)
    except InvalidAuthenticationRequest as invalid_auth_req:
        logging.getLogger().debug('received invalid authn request', exc_info=True)
        error_url = invalid_auth_req.to_error_url()
        if error_url:
            return RedirectResponse(error_url, status_code=303)

        return Response(content='Something went wrong: {}'.format(str(invalid_auth_req)), status_code=400)

    randstate = redis_cache.gen_token()
    _cache_auth_req(randstate, auth_req, authorization_request)
    return HTMLResponse(content=tvs_access.login(randstate))

def _cache_auth_req(randstate, auth_req, authorization_request):
    value = {
        'auth_req': auth_req,
        'code_challenge': authorization_request.code_challenge,
        'code_challenge_method': authorization_request.code_challenge_method
    }
    redis_cache.hset(randstate, 'auth_req', value)

def _verify_code_verifier(cc_cm, code_verifier):
    code_challenge_method = cc_cm['code_challenge_method']
    if not code_challenge_method == 'S256':
        return False

    verifier_hash = nacl.hash.sha256(code_verifier.encode('ISO_8859_1'))
    verifier_bytearray = bytearray.fromhex(verifier_hash.decode())
    code_challenge = base64.urlsafe_b64encode(verifier_bytearray).decode().replace("=","")
    print(code_challenge, code_verifier, cc_cm['code_challenge'])
    return code_challenge == cc_cm['code_challenge']

async def token_endpoint(request):
    body = await request.body()
    code = parse_qs(body.decode())['code'][0]
    code_verifier = parse_qs(body.decode())['code_verifier'][0]

    cc_cm = redis_cache.hget(code, 'cc_cm')

    if not _verify_code_verifier(cc_cm, code_verifier):
        raise HTTPException(400, detail='Bad request. code verifier not recognized')

    artifact = redis_cache.hget(code, 'arti')

    try:
        encrypted_bsn = tvs_access.resolve_artifact(artifact)
        token_response = get_oidc_provider().handle_token_request(body.decode('utf-8'),
                                                                  request.headers)

        access_key = base64.b64encode(token_response['id_token'].encode()).decode()
        redis_cache.set(access_key, encrypted_bsn)

        json_content_resp = jsonable_encoder(token_response.to_dict())
        return JSONResponse(content=json_content_resp)
    except UserNotAuthenticated as user_not_authenticated:
        logging.getLogger().debug('invalid client authentication at token endpoint', exc_info=True)
        error_resp = {
            'error': user_not_authenticated.oauth_error,
            'error_description': str(user_not_authenticated)
        }
        response = JSONResponse(jsonable_encoder(error_resp), status_code=400)
        response.headers['WWW-Authenticate'] = 'Basic'
        return response
    except InvalidClientAuthentication as invalid_client_auth:
        logging.getLogger().debug('invalid client authentication at token endpoint', exc_info=True)
        error_resp = TokenErrorResponse(error='invalid_client', error_description=str(invalid_client_auth))
        response = Response(error_resp.to_json(), status_code=401)
        response.headers['Content-Type'] = 'application/json'
        response.headers['WWW-Authenticate'] = 'Basic'
        return response
    except OAuthError as oauth_error:
        logging.getLogger().debug('invalid request: %s', str(oauth_error), exc_info=True)
        error_resp = TokenErrorResponse(error=oauth_error.oauth_error, error_description=str(oauth_error))
        response = Response(error_resp.to_json(), status_code=400)
        response.headers['Content-Type'] = 'application/json'
        return response

async def userinfo_endpoint(request: Request):
    provider  = request.app.state.provider
    body = await request.body()
    try:
        response = provider.handle_userinfo_request(body.decode('utf-8'),
                                                                request.headers)
        json_content = jsonable_encoder(response.to_dict())
        return JSONResponse(content=json_content)
    except (BearerTokenError, InvalidAccessToken) as no_access_err:
        error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(no_access_err))
        response = Response(error_resp.to_json(), status_code=401)
        response.headers['WWW-Authenticate'] = AccessToken.BEARER_TOKEN_TYPE
        response.headers['Content-Type'] = 'application/json'
        return response
