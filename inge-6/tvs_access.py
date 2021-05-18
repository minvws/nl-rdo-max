import uuid
import logging

from urllib.parse import urlparse

from fastapi.encoders import jsonable_encoder
from fastapi import Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from . import config
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

        sso_built_url = auth.login()
        request.session['AuthNRequestID'] = auth.get_last_request_id()
        # return RedirectResponse(sso_built_url)

        # ACS parts as well for mocking:
        return RedirectResponse('/acs')

    def acs(self, request: Request):
        # Mock: get token back
        access_resource = self.redis_cache.gen_token()
        # artifact = ...
        # ResolveArtifact
        # resolved_articat = ....
        resolved_artifact = str(uuid.uuid4()) # Demo purposes
        self.redis_cache.set(access_resource, resolved_artifact)

        content = {"access_resource": access_resource}

        return JSONResponse(content=content)

    def attrs(self, request: Request):
        attributes = None
        if 'access_resource' in request.session:
            attributes = self.redis_cache.get(request.session['access_resource'])
        else:
            # return access resource token not found
            raise HTTPException(status_code=404, details="access_resource not found")

        if attributes is None:
            raise HTTPException(status_code=404, details="resource not found")

        json_compatible_item_data = jsonable_encoder(attributes)
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
