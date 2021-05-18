import os

from typing import Dict
from urllib.parse import urlparse, urlencode

from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.encoders import jsonable_encoder

from oic.oic.message import TokenErrorResponse, UserInfoErrorResponse, EndSessionRequest
from pyop.access_token import AccessToken, BearerTokenError
from pyop.exceptions import InvalidAuthenticationRequest, InvalidAccessToken, InvalidClientAuthentication, OAuthError, \
                            InvalidSubjectIdentifier, InvalidClientRegistrationRequest
from pyop.util import should_fragment_encode

from .service.tvs_access import TVSRequestHandler
from .config import settings
from . import router

tvs_request_handler = TVSRequestHandler()

router = APIRouter(tags=['oidc'])

@router.get('/authentication')
def authentication_endpoint(request: Request):
     # parse authentication request
    current_app = request.app
    try:
        encoded_url = urlencode(request.query_params)
        current_app.logger.debug(encoded_url)
        auth_req = current_app.provider.parse_authentication_request(encoded_url, request.headers)
    except InvalidAuthenticationRequest as e:
        current_app.logger.debug('received invalid authn request', exc_info=True)
        error_url = e.to_error_url()
        if error_url:
            return RedirectResponse(error_url, status_code=303)
        else:
            # show error to user
            return Response(content='Something went wrong: {}'.format(str(e)), status_code=400)

    # automagic authentication
    authn_response = current_app.provider.authorize(auth_req, 'test_user')
    response_url = authn_response.request(auth_req['redirect_uri'], should_fragment_encode(auth_req))
    return RedirectResponse(response_url, status_code=303)

@router.post('/token')
def token_endpoint(request: Request):
    current_app = request.app
    try:
        token_response = current_app.provider.handle_token_request(request.body().decode('utf-8'),
                                                                   request.headers)
        json_content = jsonable_encoder(token_response.to_dict())
        return JSONResponse(content=json_content)
    except InvalidClientAuthentication as e:
        current_app.logger.debug('invalid client authentication at token endpoint', exc_info=True)
        error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
        response = Response(error_resp.to_json(), status_code=401)
        response.headers['Content-Type'] = 'application/json'
        response.headers['WWW-Authenticate'] = 'Basic'
        return response
    except OAuthError as e:
        current_app.logger.debug('invalid request: %s', str(e), exc_info=True)
        error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
        response = Response(error_resp.to_json(), status_code=400)
        response.headers['Content-Type'] = 'application/json'
        return response

@router.post('/userinfo')
def userinfo_endpoint(request: Request):
    current_app  = request.app
    try:
        response = current_app.provider.handle_userinfo_request(request.body().decode('utf-8'),
                                                                request.headers)
        json_content = jsonable_encoder(response.to_dict())
        return JSONResponse(content=json_content)
    except (BearerTokenError, InvalidAccessToken) as e:
        error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
        response = Response(error_resp.to_json(), status_code=401)
        response.headers['WWW-Authenticate'] = AccessToken.BEARER_TOKEN_TYPE
        response.headers['Content-Type'] = 'application/json'
        return response


@router.get('/.well-known/openid-configuration')
def provider_configuration(request: Request):
    json_content = jsonable_encoder(request.app.provider.provider_configuration.to_dict())
    return JSONResponse(content=json_content)

@router.get('/jwks')
def jwks_uri(request: Request):
    json_content = jsonable_encoder(request.app.provider.jwks)
    return JSONResponse(content=json_content)

@router.get("/")
def read_root(request: Request):
    url_data = urlparse(request.url._url)
    return {
        "headers": request.headers,
        "query_params": request.query_params,
        "path_params": request.path_params,
        "url": url_data.path,
    }

@router.get("/heartbeat")
def heartbeat() -> Dict[str, bool]:
    errors = list()

    # Check reachability redis
    if not redis_cache_service.redis_client.ping():
        errors.append("CANNOT REACH REDIS CLIENT ON {}:{}".format(settings.redis_host, settings.redis_port))

    # Check accessability cert and key path
    if not os.access(settings.cert_path, os.R_OK):
        errors.append("CANNOT ACCESS SAML CERT FILE")

    if not os.access(settings.cert_path, os.R_OK):
        errors.append("CANNOT ACCESS SAML KEY FILE")

    if len(errors) != 0:
        raise HTTPException(status_code=500, detail=',\n'.join(errors))

    return {"running": True}