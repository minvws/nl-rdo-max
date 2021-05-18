# import os
# import uuid
# import urllib.request

from urllib.parse import urlparse

from fastapi.encoders import jsonable_encoder
from fastapi import Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from .. import config
from .cache.redis_cache import redis_cache_service

class TVSRequestHandler:

    def __init__(self):
        self.redis_cache = redis_cache_service

    def init_saml_auth(self, req):
        auth = OneLogin_Saml2_Auth(req, custom_base_path=config.settings.saml_path)
        return auth

    # TODO: Convert to fastapi standards.
    def prepare_fastapi_request(self, request, url_data):
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

    def login(self, request: Request):
        url_data = urlparse(request.url._url)

        req = self.prepare_fastapi_request(request, url_data)
        auth = self.init_saml_auth(req)
        errors = []
        error_reason = None
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False


        sso_built_url = auth.login()
        request.session['AuthNRequestID'] = auth.get_last_request_id()
        # return RedirectResponse(sso_built_url)

        ## Here the mocking begins.
        if "Referer" not in request.headers:
            raise HTTPException(status_code=400, detail="Need referer header in order to process properly.")

        # Create token.
        token = self.redis_cache.gen_token()
        request.session['access_token'] = token
        self.redis_cache.set(token, request.session['AuthNRequestID'])
        return RedirectResponse(request.headers["Referer"])

        # resp = {
        #     'token': token,
        #     'AuthNRequest': request.session['AuthNRequestID']
        # }

        # json_compatible_item_data = jsonable_encoder(resp)
        # return JSONResponse(content=json_compatible_item_data)

    def acs(self, request: Request):
        # Mock: get token back
        if 'access_token' in request.session:
            AuthNRequest = self.redis_cache.get(request.session['access_token'])

            if "Referer" not in request.headers:
                raise HTTPException(status_code=400, detail="Need referer header in order to process properly.")
            return RedirectResponse(request.headers["Referer"])

        raise HTTPException(status_code=400, detail="No session is available to perform your request.")

        if 'samlUserdata' in request.session:
            paint_logout = True
            if len(session['samlUserdata']) > 0:
                attributes = session['samlUserdata'].items()

        raise HTTPException(status_code=404, detail=', '.join(errors))

    def attrs(self, request: Request):
        AuthNRequest = None
        if 'access_token' in request.session:
            AuthNRequest = self.redis_cache.get(request.session['access_token'])

        resp = {
            'AuthNRequest': AuthNRequest
        }

        json_compatible_item_data = jsonable_encoder(resp)
        return JSONResponse(content=json_compatible_item_data)

    def metadata(self, request: Request):
        url_data = urlparse(request.url._url)
        req = self.prepare_fastapi_request(request, url_data)
        auth = self.init_saml_auth(req)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) == 0:
            return Response(content=metadata, media_type="application/xml")

        raise HTTPException(status_code=500, detail=', '.join(errors))
