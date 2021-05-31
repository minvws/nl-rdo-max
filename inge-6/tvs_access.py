from os.path import exists

import base64
import json

from os.path import dirname, join
from jinja2 import Template

from urllib.parse import urlparse
import nacl.utils
from nacl.public import PrivateKey, Box, PublicKey
from nacl.encoding import Base64Encoder

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
    I6_PRIV_KEY = settings.bsn.i6_priv_key
    I4_PUB_KEY = settings.bsn.i4_pub_key

    def __init__(self):
        self.redis_cache = redis_cache_service
        i6_priv_key = PrivateKey(self.I6_PRIV_KEY, encoder=Base64Encoder)
        i4_pub_key = PublicKey(self.I4_PUB_KEY, encoder=Base64Encoder)

        self.box = Box(i6_priv_key, i4_pub_key)

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

    def _login_post(self, auth, return_to=None, **authn_kwargs):
        authn_request = auth.authn_request_class(auth.get_settings(), **authn_kwargs)

        url = auth.get_sso_url()
        data = authn_request.get_request()

        saml_request = OneLogin_Saml2_Utils.b64encode(
            OneLogin_Saml2_Utils.add_sign(
                data,
                auth.get_settings().get_sp_key(), auth.get_settings().get_sp_cert(),
                sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA256,
                digest_algorithm=OneLogin_Saml2_Constants.SHA256,),
        )
        # logger.debug(
        #     "Returning form-data to the user for a AuthNRequest to %s with SAMLRequest %s",
        #     url, OneLogin_Saml2_Utils.b64decode(saml_request).decode('utf-8')
        # )
        parameters = {'SAMLRequest': saml_request}

        if return_to is not None:
            parameters['RelayState'] = return_to
        else:
            parameters['RelayState'] = OneLogin_Saml2_Utils.get_self_url_no_query(data)

        return url, parameters
        template_text = template_file.read()
        template = Template(template_text)

    def _create_post_form(self, url, parameters):
        # Return HTML form
        template_file = open(settings.saml.base_dir + '/templates/authn_request.html')
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
        # print(request)
        # id_token = request.query_params['code']
        # request.session['code'] = id_token
        url_data = urlparse(request.url._url)

        req = self.prepare_fastapi_request(request, url_data)
        auth = self.init_saml_auth(req)
        # print(auth.get_settings().get_security_data())

        sso_built_url_post, parameters = self._login_post(auth, return_to='https://e039d10f9c39.ngrok.io', force_authn=True)
        # print(parameters)

        # request.session['AuthNRequestID'] = auth.get_last_request_id()
        # request.session['redirect_uri'] = request.query_params['redirect_uri']

        # if settings.mock_digid.lower() == "false":
        return self._create_post_form(sso_built_url_post, parameters)

        # access_token = request.query_params['at']
        # ACS parts as well for mocking:
        # response = RedirectResponse('/digid-mock')
        # return response

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
        # Mock: get token back
        redirect_uri = request.query_params['redirect_uri']
        code = request.query_params['code']
        state = request.query_params['state']
        bsn = request.query_params['bsn']

        self.redis_cache.set(code,self._encrypt_encode_bsn(bsn).decode())

        redirect_uri += f'?code={code}&state={state}'
        return RedirectResponse(redirect_uri)

    def _encrypt_encode_bsn(self, bsn):
        encrypted_bsn, nonce = self._encrypt_bsn(bsn)
        payload = {
            'bsn': Base64Encoder.encode(encrypted_bsn).decode(),
            'nonce': Base64Encoder.encode(nonce).decode()
        }
        return base64.b64encode(json.dumps(payload).encode())

    def _encrypt_bsn(self, bsn):
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        encrypted_bsn = self.box.encrypt(bsn.encode(), nonce=nonce, encoder=Base64Encoder)
        return encrypted_bsn, nonce

    async def bsn_attribute(self, request: Request):
        id_token = await request.body()
        attributes = self.redis_cache.get(id_token.decode())
        if attributes is None:
            raise HTTPException(status_code=408, detail="Resource expired.Try again after /authorize", )

        decoded_json = base64.b64decode(attributes).decode()

        return JSONResponse(content=json.loads(decoded_json))

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
