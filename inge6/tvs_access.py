from os.path import exists

import requests
import base64
import uuid
import json

from jinja2 import Template

from urllib.parse import urlparse
from jwkest.jwt import JWT

from fastapi.encoders import jsonable_encoder
from fastapi import Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.security.utils import get_authorization_scheme_param

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from .config import settings
from .bsn_encrypt import BSNEncrypt
from .cache.redis_cache import redis_cache_service
from .saml.request_builder import AuthNRequest, ArtifactResolveRequest
from .saml.response_parser import IdPMetadataParser, ArtifactResponseParser

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
        # If server is behinan uit dat het advies tot vragen en onrust zal leiden bij mensen die een prikafspraak voor het Janssen-vaccin hebben staan. "Afspraken vallen uit omdat ze verzet moeten worden, de callcenters wordd proxys or balancers use the HTTP_X_FORWARDED fields
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

    def _login_post(self, auth, relay_state):
        url = auth.get_sso_url()

        saml_request = AuthNRequest()
        parameters = {
            'SAMLRequest': saml_request.get_base64_string().decode(),
            'RelayState': relay_state
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

    def login(self, request: Request, randstate: str):
        url_data = urlparse(request.url._url)

        req = self.prepare_fastapi_request(request, url_data)
        auth = self.init_saml_auth(req)

        sso_built_url_post, parameters = self._login_post(auth, relay_state=randstate)

        if settings.mock_digid.lower() == "true" and not 'force_digid' in request.query_params:
            return self._create_post_form(f'/digid-mock?state={randstate}', parameters)

        return self._create_post_form(sso_built_url_post, parameters)

    async def digid_mock(self, request: Request):
        body = await request.form()
        state = request.query_params['state']
        relay_state = body['RelayState']
        artifact = str(uuid.uuid4())
        http_content = f"""
        <html>
        <h1> DIGID MOCK </h1>
        <form method="GET" action="/digid-mock-catch">
            <label for="bsn">BSN Value:</label><br>
            <input type="text" id="bsn" value="900212640" name="bsn"><br>
            <input type="hidden" name="SAMLart" value="{artifact}">
            <input type="hidden" name="RelayState" value="{relay_state}">
            <input type="submit" value="Login">
        </form>
        <a href='/login-digid?force_digid&state={state}' style='font-size:36; background-color:purple; display:box'>Actual BSN</a>
        </html>
        """
        return HTMLResponse(content=http_content, status_code=200)

    def digid_mock_catch(self, request: Request):
        bsn = request.query_params['bsn']
        relay_state = request.query_params['RelayState']
        response_uri = '/acs' + f'?SAMLart={bsn}&RelayState={relay_state}'
        return RedirectResponse(response_uri, status_code=303)

    def acs(self, request: Request):
        state = request.query_params['RelayState']
        artifact = request.query_params['SAMLart']

        auth_req_dict = self.redis_cache.hget(state, 'auth_req')
        auth_req = auth_req_dict['auth_req']

        authn_response = request.app.provider.authorize(auth_req, 'test_user')
        response_url = authn_response.request(auth_req['redirect_uri'], False)
        code = authn_response['code']

        self.redis_cache.hset(code, 'arti', artifact)
        self._store_code_challenge(code, auth_req_dict['code_challenge'], auth_req_dict['code_challenge_method'])
        return RedirectResponse(response_url, status_code=303)

    def _store_code_challenge(self, code, code_challenge, code_challenge_method):
        value = {
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method
        }
        self.redis_cache.hset(code, 'cc_cm', value)

    def resolve_artifact(self, artifact):

        if settings.mock_digid.lower() == "true":
            return self._bsn_encrypt._symm_encrypt_bsn(artifact)

        resolve_artifact_req = ArtifactResolveRequest(artifact).get_xml()
        url = self.idp_metadata.get_artifact_rs()['location']
        headers = {
            'SOAPAction' : '"https://artifact-pp2.toegang.overheid.nl/kvs/rd/resolve_artifact"',
            'content-type': 'text/xml'
            }
        resolved_artifact = requests.post(url, headers=headers, data=resolve_artifact_req, cert=('saml/certs/sp.crt', 'saml/certs/sp.key'))
        bsn = ArtifactResponseParser(resolved_artifact.text).get_bsn()
        encrypted_bsn = self._bsn_encrypt._symm_encrypt_bsn(bsn)
        return encrypted_bsn

    def disable_access_token(self, b64_id_token):
        # TODO
        self.redis_cache.delete(b64_id_token.decode(), '')

    def repack_bsn_attribute(self, attributes, nonce):
        decoded_json = base64.b64decode(attributes).decode()
        bsn_dict = json.loads(decoded_json)
        bsn = self._bsn_encrypt._symm_decrypt_bsn(bsn_dict)
        return self._bsn_encrypt._pub_encrypt_bsn(bsn, nonce)

    def _jwt_payload(self, jwt: str) -> dict:
        jwt_token = JWT().unpack(jwt)
        return json.loads(jwt_token.part[1].decode())

    def _validate_jwt_token(self, jwt):
        # TODO
        return True

    async def bsn_attribute(self, request: Request):
        #Parse JWT token
        authorization: str = request.headers.get("Authorization")
        scheme, id_token = get_authorization_scheme_param(authorization)

        if not scheme == 'Bearer' or not self._validate_jwt_token(id_token):
            raise HTTPException(status_code=401, detail="Not authorized")

        payload = self._jwt_payload(id_token)
        at_hash = payload['at_hash']

        b64_id_token = base64.b64encode(id_token.encode())
        attributes = self.redis_cache.get(b64_id_token.decode())
        self.disable_access_token(b64_id_token)

        if attributes is None:
            raise HTTPException(status_code=408, detail="Resource expired.Try again after /authorize", )

        encrypted_bsn = self.repack_bsn_attribute(attributes, at_hash)
        jsonified_encrypted_bsn = jsonable_encoder(encrypted_bsn)
        return JSONResponse(content=jsonified_encrypted_bsn)

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
