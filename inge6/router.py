import os
from typing import Dict
from urllib.parse import urlparse

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.encoders import jsonable_encoder

from .tvs_access import TVSRequestHandler
from .authorize import AuthorizationHandler
from .cache.redis_cache import redis_cache_service
from .config import settings
from . import router

tvs_request_handler = TVSRequestHandler()
authorization_handler = AuthorizationHandler()

router = APIRouter()

# TODO: Support GET and POST methods. Serializing the request parameters or Form.
@router.get('/authorize')
def authorize(request: Request):
    # TODO: Only allow scope=openid, enforce if missing?
    return authorization_handler.authorize(request)

@router.post('/accesstoken')
async def token_endpoint(request: Request):
    ''' Expect a request with a body containing the grant_type.'''
    return await authorization_handler.token_endpoint(request)

@router.api_route('/userinfo', methods=["GET", "POST"])
async def userinfo_endpoint(request: Request):
    return authorization_handler.userinfo_endpoint(request)

@router.get('/login-digid')
def login_digid(request: Request):
    ## TODO: Check valid token.
    state = request.query_params['state']
    return HTMLResponse(content=tvs_request_handler.login(request, state))

@router.get('/metadata')
def metadata(request: Request):
    return tvs_request_handler.metadata(request)

@router.post('/digid-mock')
async def digid_mock(request: Request):
    return await tvs_request_handler.digid_mock(request)

@router.get('/digid-mock-catch')
def digid_mock_catch(request: Request):
    return tvs_request_handler.digid_mock_catch(request)

@router.get('/acs')
def assertion_consumer_service(request: Request):
    ## TODO: Check valid token.
    return tvs_request_handler.acs(request)

@router.post('/bsn_attribute')
async def bsn_attribute(request: Request):
    return await tvs_request_handler.bsn_attribute(request)
    # return Response(content="MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzpEliQZGIthee86WIg0w599yMlSzcg8ojyA==", status_code=200)

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
    # json = await request.json()
    return {
        "headers": request.headers,
        "query_params": request.query_params,
        "path_params": request.path_params,
        "url": url_data.path,
        # "json": json
    }

@router.get("/heartbeat")
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