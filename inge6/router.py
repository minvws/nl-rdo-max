from inge6.oidc_provider import get_oidc_provider
import os
from typing import Dict, Optional
from urllib.parse import urlencode
from urllib.parse import urlparse

from fastapi import APIRouter, Form, Depends, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.encoders import jsonable_encoder

from . import tvs_access as tvs_request_handler
from . import authorize as authorization_handler
from . import router

from .config import settings
from .models import AccesstokenRequest, AuthorizeRequest

from .cache import get_redis_client

router = APIRouter()

@router.get('/authorize')
def authorize(request: Request, authorize: AuthorizeRequest = Depends()):
    return authorization_handler.authorize(authorize, request.headers)

@router.post('/accesstoken')
async def token_endpoint(request: Request):
    ''' Expect a request with a body containing the grant_type.'''
    return await authorization_handler.token_endpoint(request)

@router.api_route('/userinfo', methods=["GET", "POST"])
async def userinfo_endpoint(request: Request):
    return authorization_handler.userinfo_endpoint(request)

@router.get('/metadata')
def metadata(request: Request):
    return tvs_request_handler.metadata(request)

@router.get('/acs')
def assertion_consumer_service(request: Request):
    return tvs_request_handler.acs(request)

@router.post('/bsn_attribute')
def bsn_attribute(request: Request):
    return tvs_request_handler.bsn_attribute(request)

@router.get('/.well-known/openid-configuration')
def provider_configuration(request: Request):
    json_content = jsonable_encoder(get_oidc_provider().provider_configuration.to_dict())
    return JSONResponse(content=json_content)

@router.get('/jwks')
def jwks_uri(request: Request):
    json_content = jsonable_encoder(get_oidc_provider().jwks)
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
    if not get_redis_client().ping():
        errors.append("CANNOT REACH REDIS CLIENT ON {}:{}".format(settings.redis.host, settings.redis.port))

    # Check accessability cert and key path
    if not os.access(settings.saml.cert_path, os.R_OK):
        errors.append("CANNOT ACCESS SAML CERT FILE")

    if not os.access(settings.saml.cert_path, os.R_OK):
        errors.append("CANNOT ACCESS SAML KEY FILE")

    if len(errors) != 0:
        raise HTTPException(status_code=500, detail=',\n'.join(errors))

    return {"running": True}


## MOCK ENDPOINTS:

@router.get('/login-digid')
def login_digid(state: str, force_digid: Optional[bool] = None):
    return HTMLResponse(content=tvs_request_handler.login(state, force_digid))

@router.post('/digid-mock')
async def digid_mock(request: Request):
    return await tvs_request_handler.digid_mock(request)

@router.get('/digid-mock-catch')
def digid_mock_catch(request: Request):
    return tvs_request_handler.digid_mock_catch(request)
