import logging
from logging import Logger

import re

import redis.exceptions

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.encoders import jsonable_encoder

from .config import settings
from .cache import get_redis_client
from .models import AuthorizeRequest, DigiDMockRequest, DigiDMockCatchRequest, LoginDigiDRequest, SorryPageRequest
from .provider import get_provider
from .digid_mock import (
    digid_mock as dmock,
    digid_mock_catch as dmock_catch
)

log: Logger = logging.getLogger(__package__)
log.setLevel(getattr(logging, settings.loglevel.upper()))

router = APIRouter()

@router.get(settings.authorize_endpoint)
def authorize(request: Request, authorize_req: AuthorizeRequest = Depends()):
    return get_provider().authorize_endpoint(authorize_req, request.headers, request.client.host)

@router.post(settings.accesstoken_endpoint)
async def token_endpoint(request: Request):
    ''' Expect a request with a body containing the grant_type.'''
    body = await request.body()
    headers = request.headers
    return get_provider().token_endpoint(body, headers)

@router.get('/metadata/{id_provider}')
def metadata(id_provider: str):
    return get_provider().metadata(id_provider)

@router.get('/acs')
def assertion_consumer_service(request: Request):
    return get_provider().assertion_consumer_service(request)

@router.post('/bsn_attribute')
async def bsn_attribute(request: Request):
    return get_provider().bsn_attribute(request)

@router.get('/.well-known/openid-configuration')
def provider_configuration():
    json_content = jsonable_encoder(get_provider().provider_configuration.to_dict())
    return JSONResponse(content=json_content)

@router.get(settings.jwks_endpoint)
def jwks_uri():
    json_content = jsonable_encoder(get_provider().jwks)
    return JSONResponse(content=json_content)

@router.get('/sorry-something-went-wrong')
def sorry_something_went_wrong(request: SorryPageRequest = Depends()):
    return get_provider().sorry_something_went_wrong(request)

@router.get("/")
def read_root():
    return HTMLResponse("Many Authentication eXchange")

@router.get(settings.health_endpoint)
def health() -> JSONResponse:
    try:
        redis_healthy = get_redis_client().ping()
    except redis.exceptions.RedisError as exception:
        log.exception('Redis server is not reachable. Attempted: %s:%s, ssl=%s', settings.redis.host, settings.redis.port, settings.redis.ssl, exc_info=exception)
        redis_healthy = False

    healthy = redis_healthy
    response = {"healthy": healthy, "results": [{"healthy": redis_healthy, "service": "keydb"}]}
    return JSONResponse(content=jsonable_encoder(response), status_code=200 if healthy else 500)

## MOCK ENDPOINTS:
if hasattr(settings, 'mock_digid') and settings.mock_digid.lower() == 'true':
    # pylint: disable=wrong-import-position, c-extension-no-member, wrong-import-order
    from lxml import etree
    from urllib.parse import parse_qs # pylint: disable=wrong-import-order
    from .provider import _post_login
    from io import StringIO

    @router.get('/login-digid')
    def login_digid(login_digid_req: LoginDigiDRequest = Depends(LoginDigiDRequest.from_request)):
        id_provider = get_provider().get_id_provider(login_digid_req.idp_name)
        return _post_login(login_digid_req, id_provider) # pylint: disable=protected-access

    @router.post('/digid-mock')
    async def digid_mock(digid_mock_req: DigiDMockRequest = Depends(DigiDMockRequest.from_request)):  # pylint: disable=invalid-name
        return dmock(digid_mock_req)

    @router.get('/digid-mock-catch')
    async def digid_mock_catch(request: DigiDMockCatchRequest = Depends()):
        return dmock_catch(request)

    @router.get('/consume_bsn/{bsn}')
    def consume_bsn_for_token(bsn: str, request: Request, authorize_req: AuthorizeRequest = Depends()):
        response = get_provider().authorize_endpoint(authorize_req, request.headers, request.client.host)
        status_code = response.status_code
        if status_code != 200:
            log.debug('Status code 200 was expected, but was %s', response.status_code)
            if 300 <= status_code < 400:
                redirect = response.raw_headers[0][1].decode()
                raise HTTPException(status_code=400, detail='200 expected, got {} with redirect uri: {}'.format(status_code, redirect))
            raise HTTPException(status_code=400, detail='detail authorize response status code was {}, but 200 was expected'.format(status_code))

        parser = etree.HTMLParser()
        tree   = etree.parse(StringIO(response.body.decode()), parser)
        relay_state = tree.getroot().find('.//input[@name="RelayState"]').attrib['value']

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
        redirect_url = re.search(r"<meta http-equiv=\"refresh\" content=\"0;url=(.*?)\" />", response.body.decode())
        if redirect_url is None:
            raise HTTPException(status_code=400, detail="No valid refresh url found")

        response_qargs = parse_qs(redirect_url[1].split('?')[1])
        content = jsonable_encoder(response_qargs)
        return JSONResponse(content=content)
