import os
import uuid
from typing import Optional, List, Dict

import urllib.request
from urllib.parse import urlparse

from starlette.middleware.sessions import SessionMiddleware

from fastapi.encoders import jsonable_encoder
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

import redis

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from . import config

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="example")

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=config.settings.saml_path)
    return auth

# TODO: Convert to fastapi standards.
def prepare_flask_request(request, url_data):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        'https': 'on' if request.url.scheme == 'https' else 'off',
        'http_host': request.client.host,
        'server_port': url_data.port,
        'script_name': url_data.path,
        'get_data': request.query_params,
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.body
    }

@app.get('/login')
def index(request: Request):
    url_data = urlparse(request.url._url)

    req = prepare_flask_request(request, url_data)
    auth = init_saml_auth(req)
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False


    if 'sso' in request.query_params:
        sso_built_url = auth.login()
        request.session['AuthNRequestID'] = auth.get_last_request_id()
        # return RedirectResponse(sso_built_url)

        ## Here the mocking begins.
        if "Referer" not in request.headers:
            raise HTTPException(status_code=400, detail="Need referer header in order to process properly.")

        # Create token.
        token = str(uuid.uuid4())
        request.session['access_token'] = token
        redis_client.set(token, request.session['AuthNRequestID'])
        return RedirectResponse(request.headers["Referer"])

        # resp = {
        #     'token': token,
        #     'AuthNRequest': request.session['AuthNRequestID']
        # }

        # json_compatible_item_data = jsonable_encoder(resp)
        # return JSONResponse(content=json_compatible_item_data)

    elif 'slo' in request.query_params:
        if 'access_token' in request.session:
            del request.session['AuthNRequestID']
            redis_client.delete(request.session['access_token'])
            return {"status_code": 200}

        raise HTTPException(status_code=400, detail="No session exists")
    elif 'acs' in request.query_params:

        # Mock: get token back
        if 'access_token' in request.session:
            AuthNRequest = redis_client.get(request.session['access_token'])

            if "Referer" not in request.headers:
                raise HTTPException(status_code=400, detail="Need referer header in order to process properly.")
            return RedirectResponse(request.headers["Referer"])

        raise HTTPException(status_code=400, detail="No session is available to perform your request.")

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    raise HTTPException(status_code=404, detail=', '.join(errors))


@app.get('/attrs/')
def attrs(request: Request):
    AuthNRequest = None
    if 'access_token' in request.session:
        AuthNRequest = redis_client.get(request.session['access_token'])

    resp = {
        'AuthNRequest': AuthNRequest
    }

    json_compatible_item_data = jsonable_encoder(resp)
    return JSONResponse(content=json_compatible_item_data)

@app.get('/metadata/')
def metadata(request: Request):
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        return Response(content=metadata, media_type="application/xml")

    raise HTTPException(status_code=500, detail=', '.join(errors))

# @app.get("/value/{value_id}")
# def get_value(value_id):
#     return {value_id: redis_client.get(value_id)}

# @app.post("/value/")
# def set_value(name: str, value: str):
#     redis_client.set(name, value)
#     return {name: value}

@app.get("/")
def read_root(request: Request):
    url_data = urlparse(request.url._url)
    return {
        "headers": request.headers,
        "query_params": request.query_params,
        "path_params": request.path_params,
        "url": url_data.hostname,
    }

