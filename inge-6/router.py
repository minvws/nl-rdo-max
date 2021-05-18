import os

from typing import Dict
from urllib.parse import urlparse

from fastapi import APIRouter
from fastapi import Request, Response, HTTPException

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
    return {'name': 'authentication'}

@router.post('/token')
def token_endpoint():
    return {'name': 'tokenendpoint'}

@router.post('/userinfo')
def userinfo_endpoint():
    return {'name': 'userinfo'}

@router.get('/.well-known/openid-configuration')
def provider_configuration():
    return {'name': 'provider-conf'}

@router.get('/jwks')
def jwks_uri():
    return {'name': 'provider-jwks'}

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