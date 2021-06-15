import os
import logging

from typing import Dict, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.encoders import jsonable_encoder

from .config import settings
from .cache import get_redis_client
from .models import AuthorizeRequest
from .provider import get_provider
from .digid_mock import (
    digid_mock as dmock,
    digid_mock_catch as dmock_catch
)

router = APIRouter()

@router.get('/authorize')
def authorize(request: Request, authorize_req: AuthorizeRequest = Depends()):
    return get_provider().authorize_endpoint(authorize_req, request.headers)

@router.post('/accesstoken')
async def token_endpoint(request: Request):
    ''' Expect a request with a body containing the grant_type.'''
    body = await request.body()
    headers = request.headers
    return get_provider().token_endpoint(body, headers)

@router.get('/metadata')
def metadata():
    return get_provider().metadata()

@router.get('/acs')
def assertion_consumer_service(request: Request):
    return get_provider().assertion_consumer_service(request)

@router.post('/bsn_attribute')
def bsn_attribute(request: Request):
    return get_provider().bsn_attribute(request)

@router.get('/.well-known/openid-configuration')
def provider_configuration():
    json_content = jsonable_encoder(get_provider().provider_configuration.to_dict())
    return JSONResponse(content=json_content)

@router.get('/jwks')
def jwks_uri():
    json_content = jsonable_encoder(get_provider().jwks)
    return JSONResponse(content=json_content)

@router.get("/")
async def read_root(request: Request):
    url_data = urlparse(request.url._url) # pylint: disable=protected-access
    return {
        "headers": request.headers,
        "query_params": request.query_params,
        "path_params": request.path_params,
        "url": url_data.path
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
if settings.mock_digid.lower() == 'true':
    # pylint: disable=wrong-import-position, c-extension-no-member, wrong-import-order
    from lxml import etree
    from urllib.parse import parse_qs # pylint: disable=wrong-import-order

    @router.get('/login-digid')
    def login_digid(state: str, force_digid: Optional[bool] = None):
        return HTMLResponse(content=get_provider()._login(state, force_digid)) # pylint: disable=protected-access

    @router.post('/digid-mock')
    async def digid_mock(request: Request):
        return await dmock(request)

    @router.get('/digid-mock-catch')
    async def digid_mock_catch(request: Request):
        return await dmock_catch(request)

    @router.get('/consume_bsn/{bsn}')
    def consume_bsn_for_token(bsn: str, request: Request, authorize_req: AuthorizeRequest = Depends()):
        response = get_provider().authorize_endpoint(authorize_req, request.headers)
        status_code = response.status_code
        if status_code != 200:
            logging.debug('Status code 200 was expected, but was %s', response.status_code)
            if 300 <= status_code < 400:
                redirect = response.raw_headers[0][1].decode()
                raise HTTPException(status_code=400, detail='200 expected, got {} with redirect uri: {}'.format(status_code, redirect))
            raise HTTPException(status_code=400, detail='detail authorize response status code was {}, but 200 was expected'.format(status_code))

        response_tree = etree.fromstring(response.__dict__['body'].decode()).getroottree().getroot()
        relay_state = response_tree.find('.//input[@name="RelayState"]').attrib['value']

        # pylint: disable=too-few-public-methods, too-many-ancestors, super-init-not-called
        class AcsReq(Request):
            def __init__(self):
                pass

            @property
            def query_params(self):
                return {
                'RelayState': relay_state,
                'SAMLart': bsn,
                'mocking': '1'
            }

        response = get_provider().assertion_consumer_service(AcsReq())
        response_qargs = parse_qs(response.headers["location"].split('?')[1])
        content = jsonable_encoder(response_qargs)
        return JSONResponse(content=content)
