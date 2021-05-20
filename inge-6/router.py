import os
from typing import Dict
from urllib.parse import urlparse

from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.encoders import jsonable_encoder

from .tvs_access import TVSRequestHandler
from .authorize import AuthorizationHandler
from .cache.redis_cache import redis_cache_service
from .config import settings
from . import router

tvs_request_handler = TVSRequestHandler()
authorization_handler = AuthorizationHandler()

router = APIRouter()

@router.get('/authorize')
def authorize(request: Request):
    return authorization_handler.authorize(request)

@router.post('/token?')
async def token_endpoint(request: Request):
    return authorization_handler.token_endpoint(request)

@router.post('/userinfo?')
async def userinfo_endpoint(request: Request):
    return authorization_handler.userinfo_endpoint(request)

@router.get('/login-digid')
def login_digid(request: Request):
    return tvs_request_handler.login(request)

@router.get('/metadata')
def metadata(request: Request):
    return tvs_request_handler.metadata(request)

@router.get('/digid-mock')
def digid_mock(request: Request):
    return tvs_request_handler.digid_mock(request)

@router.get('/acs')
def assertion_consumer_service(request: Request):
    return tvs_request_handler.acs(request)

@router.get('/attrs')
def attrs(request: Request):
    return tvs_request_handler.attrs(request)

@router.get('/.well-known/openid-configuration')
def provider_configuration(request: Request):
    json_content = jsonable_encoder(request.app.provider.provider_configuration.to_dict())
    return JSONResponse(content=json_content)

@router.get('/jwks')
def jwks_uri(request: Request):
    json_content = jsonable_encoder(request.app.provider.jwks)
    return JSONResponse(content=json_content)

@router.get("/")
async def read_root(request: Request):
    url_data = urlparse(request.url._url)
    return {
        "headers": request.headers,
        "query_params": request.query_params,
        "path_params": request.path_params,
        "url": url_data.path
    }

@router.get("/heartbeat?")
def heartbeat() -> Dict[str, bool]:
    errors = list()

    # Check reachability redis
    if not redis_cache_service.redis_client.ping():
        errors.append("CANNOT REACH REDIS CLIENT ON {}:{}".format(settings.redis.host, settings.redis.port))

    # Check accessability cert and key path
    if not os.access(settings.saml.cert_path, os.R_OK):
        errors.append("CANNOT ACCESS SAML CERT FILE")

    if not os.access(settings.saml.cert_path, os.R_OK):
        errors.append("CANNOT ACCESS SAML KEY FILE")

    if len(errors) != 0:
        raise HTTPException(status_code=500, detail=',\n'.join(errors))

    return {"running": True}