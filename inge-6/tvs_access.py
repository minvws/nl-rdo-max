from os.path import exists

import requests
import base64
import json

from os.path import dirname, join
from jinja2 import Template

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
from .bsn_encrypt import BSNEncrypt
from .cache.redis_cache import redis_cache_service
from .saml_request_builder import AuthNRequest, ArtifactResolveRequest
from .saml_response_parser import IdPMetadataParser

class TVSRequestHandler:

    def __init__(self):
        self.redis_cache = redis_cache_service
        self._bsn_encrypt = BSNEncrypt()
        self.idp_metadata = IdPMetadataParser()

    def _create_idp_sp_settings(self):
        idp_data = OneLogin_Saml2_IdPMetadataParser.parse_remote(
            'https://pp2.toegang.overheid.nl/kvs/rd/metadata',
            required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST,
            required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST,
        )

        base_settings = OneLogin_Saml2_Settings(custom_base_path=settings.saml.base_dir, sp_validation_only=True)
        sp_settings = {
            'sp':  base_settings.get_sp_data(),
        }
        merged_settings = OneLogin_Saml2_IdPMetadataParser.merge_settings(
                                                                    sp_settings,
                                                                    idp_data
                                                                )

        # Append the advanced settings to the file.
        advanced_filename = base_settings.get_base_path() + 'advanced_settings.json'
        if exists(advanced_filename):
            with open(advanced_filename, 'r') as json_data:
                merged_settings.update(json.loads(json_data.read()))  # Merge settings

        return merged_settings

    def init_saml_auth(self, req):
        merged_settings = self._create_idp_sp_settings()
        auth = OneLogin_Saml2_Auth(req, merged_settings, custom_base_path=settings.saml.base_dir)
        return auth

    # TODO: Convert to fastapi standards.
    def prepare_fastapi_request(self, request, url_data):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        return {
            'https': 'on' if request.url.scheme == 'https' else 'off',
            'http_host': settings.issuer,
            'server_port': 443, # configbaar
            'script_name': url_data.path,
            'get_data': request.query_params,
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            'post_data': request.body
        }

    def _login_post(self, auth, return_to):
        url = auth.get_sso_url()

        saml_request = AuthNRequest()
        parameters = {
            'SAMLRequest': saml_request.get_base64_string().decode(),
            'RelayState': return_to
            }

        return url, parameters

    def _create_post_form(self, url, parameters):
        # Return HTML form
        template_file = open(settings.saml.base_dir + '/templates/html/authn_request.html')
        template_text = template_file.read()
        template = Template(template_text)

        context = {
            'sso_url': url,
            'saml_request': parameters['SAMLRequest'],
            'relay_state': parameters['RelayState']
        }
        html = template.render(context)

        return html

    def login(self, request: Request):
        url_data = urlparse(request.url._url)

        req = self.prepare_fastapi_request(request, url_data)
        auth = self.init_saml_auth(req)

        return_to = url_data.netloc + url_data.path
        sso_built_url_post, parameters = self._login_post(auth, return_to=return_to)
        # print(parameters)

        # request.session['AuthNRequestID'] = auth.get_last_request_id()
        # request.session['redirect_uri'] = request.query_params['redirect_uri']

        return self._create_post_form(sso_built_url_post, parameters)

    def digid_mock(self, request: Request):
        code = request.query_params['code']
        redirect_uri = request.query_params['redirect_uri']
        state = request.query_params['state']
        http_content = f"""
        <html>
        <h1> DIGID MOCK </h1>
        <form method="GET" action="/acs">
            <label for="bsn">BSN Value:</label><br>
            <input type="text" id="bsn" value="900212640" name="bsn"><br>
            <input type="hidden" name="code" value="{code}">
            <input type="hidden" name="state" value="{state}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="submit" value="Login">
        </form>
        </html>
        """
        return HTMLResponse(content=http_content, status_code=200)

    def acs(self, request: Request):
        relay_state = request.query_params['RelayState']
        artifact = request.query_params['SAMLart']
        resolve_artifact_req = ArtifactResolveRequest(artifact)
        # relay_state = ...
        url = self.idp_metadata.get_artifact_rs['location']
        headers = {'content-type': 'text/xml'}
        resolved_artifact = requests.post(url, headers=headers, data=resolve_artifact_req)
        # resolved_articat = ....
        # Decrypt ...
        # Encrypt ...

        return RedirectResponse(request.session['redirect_uri'])

    def disable_access_token(self, b64_id_token):
        pass

    async def bsn_attribute(self, request: Request):
        access_token = await request.json()

        b64_id_token = base64.b64encode(access_token['id_token'].encode())

        attributes = self.redis_cache.get(b64_id_token.decode())
        if attributes is None:
            raise HTTPException(status_code=408, detail="Resource expired.Try again after /authorize", )

        decoded_json = base64.b64decode(attributes).decode()
        bsn_dict = json.loads(decoded_json)
        bsn = self._bsn_encrypt._symm_decrypt_bsn(bsn_dict)
        encrypted_bsn = self._bsn_encrypt._pub_encrypt_bsn(bsn, access_token['access_token'])

        jsonified_encrypted_bsn = jsonable_encoder(encrypted_bsn)
        return JSONResponse(content=jsonified_encrypted_bsn)

    def metadata(self, request: Request):
        url_data = urlparse(request.url._url)
        req = self.prepare_fastapi_request(request, url_data)
        auth = self.init_saml_auth(req)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        print(saml_settings.get_idp_data())

        if len(errors) == 0:
            return Response(content=metadata, media_type="application/xml")

        raise HTTPException(status_code=500, detail=', '.join(errors))
