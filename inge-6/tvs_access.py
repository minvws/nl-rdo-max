import uuid
import logging
import base64
import json

from urllib.parse import urlparse

from fastapi.encoders import jsonable_encoder
from fastapi import Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from .config import settings
from .cache.redis_cache import redis_cache_service

class TVSRequestHandler:

    def __init__(self):
        self.redis_cache = redis_cache_service

    def init_saml_auth(self, req):
        idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(
            'https://pp2.toegang.overheid.nl/kvs/rd/metadata',
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST,
        )
        # auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.saml.base_dir)
        sp_settings = OneLogin_Saml2_Settings(custom_base_path=settings.saml.base_dir, sp_validation_only=True)
        merged_settings_dict = {
            'sp': sp_settings.get_sp_data()
        }
        merged_settings_dict['idp'] = idp_data['idp']

        saml_settings = OneLogin_Saml2_Settings(merged_settings_dict)
        auth = OneLogin_Saml2_Auth(req, saml_settings)
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
        # id_token = request.query_params['code']
        # request.session['code'] = id_token
        url_data = urlparse(request.url._url)

        req = self.prepare_fastapi_request(request, url_data)
        auth = self.init_saml_auth(req)

        sso_built_url = auth.login()
        request.session['AuthNRequestID'] = auth.get_last_request_id()
        request.session['redirect_uri'] = request.query_params['redirect_uri']
        request.app.logger.debug('*****%s', request.query_params['redirect_uri'])

        if settings.mock_digid.lower() == "false":
            return RedirectResponse(sso_built_url)

        access_token = request.query_params['at']
        # ACS parts as well for mocking:
        response = RedirectResponse('/digid-mock?at=' + access_token)
        return response

    def digid_mock(self, request: Request):
        access_token = request.query_params['at']
        http_content = f"""
        <html>
        <h1> DIGID MOCK </h1>
        {access_token}
        <a href='/acs?at={access_token}' style='font-size:36; background-color:purple; display:box'>login</a>
        </html>
        """
        return HTMLResponse(content=http_content, status_code=200)

    def acs(self, request: Request):
        # Mock: get token back
        at = request.query_params['at']
        request.app.logger.debug("BASE64 ACCESS RESOURCE: %s", at)
        access_token = base64.b64decode(at).decode()
        request.app.logger.debug("ACCESS RESOURCE: %s", access_token)
        # id_token = ...
        # artifact = ...
        # ResolveArtifact
        # resolved_articat = ....
        resolved_artifact = str(uuid.uuid4()) # Demo purposes
        self.redis_cache.set(access_token, resolved_artifact)
        return RedirectResponse(request.session['redirect_uri'])

    def bsn_attribute(self, request: Request):
        attributes = None
        if 'id_token' in request.session:
            attributes = self.redis_cache.get(request.session['id_token'])
        else:
            # Response redirect to /authorize?
            raise HTTPException(status_code=405, detail="Method not allowed, authorize first.")

        if attributes is None:
            raise HTTPException(status_code=408, detail="Resource expired.Try again after /authorize", )

        json_compatible_item_data = jsonable_encoder(attributes)
        return JSONResponse(content=json_compatible_item_data)

    def metadata(self, request: Request):
        url_data = urlparse(request.url._url)
        req = self.prepare_fastapi_request(request, url_data)
        auth = self.init_saml_auth(req)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        if len(errors) == 0:
            return Response(content=metadata, media_type="application/xml")

        raise HTTPException(status_code=500, detail=', '.join(errors))
