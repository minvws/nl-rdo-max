from urllib.parse import parse_qs

import base64
import uuid
from urllib.parse import urlencode

import nacl.hash

from fastapi import  Request, Response, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from fastapi.encoders import jsonable_encoder

from oic.oic.message import TokenErrorResponse, UserInfoErrorResponse
from pyop.access_token import AccessToken, BearerTokenError
from pyop.exceptions import InvalidAuthenticationRequest, InvalidAccessToken, InvalidClientAuthentication, OAuthError

from pyop.util import should_fragment_encode

from .config import settings
from .cache.redis_cache import redis_cache_service
from .tvs_access import TVSRequestHandler

class AuthorizationHandler:

    def __init__(self):
        self.redis_cache = redis_cache_service
        self.tvs_handler = TVSRequestHandler()

    def authorize(self, request: Request):
        # TODO: Assume scope parameter: scope=openid if not exists?
        current_app = request.app
        try:
            auth_req = current_app.provider.parse_authentication_request(urlencode(request.query_params), request.headers)
        except InvalidAuthenticationRequest as e:
            current_app.logger.debug('received invalid authn request', exc_info=True)
            error_url = e.to_error_url()
            if error_url:
                return RedirectResponse(error_url, status_code=303)
            else:
                # show error to user
                return Response(content='Something went wrong: {}'.format(str(e)), status_code=400)

        code_challenge = request.query_params['code_challenge']
        code_challenge_method = request.query_params['code_challenge_method']

        randstate = self.redis_cache.gen_token()
        self._cache_auth_req(randstate, auth_req, code_challenge, code_challenge_method)
        return HTMLResponse(content=self.tvs_handler.login(request, randstate))

    def _cache_auth_req(self, randstate, auth_req, code_challenge, code_challenge_method):
        value = {
            'auth_req': auth_req,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method
        }
        self.redis_cache.hset(randstate, 'auth_req', value)

    def _verify_code_verifier(self, cc_cm, code_verifier):
        code_challenge_method = cc_cm['code_challenge_method']
        if not code_challenge_method == 'S256':
            return False

        verifier_hash = nacl.hash.sha256(code_verifier.encode())
        code_challenge = base64.urlsafe_b64encode(verifier_hash).decode().replace('=','')
        return code_challenge == cc_cm['code_challenge']

    async def token_endpoint(self, request):
        current_app = request.app
        body = await request.body()
        code = parse_qs(body.decode())['code'][0]
        code_verifier = parse_qs(body.decode())['code_verifier'][0]
        cc_cm = self.redis_cache.hget(code, 'cc_cm')

        if not self._verify_code_verifier(cc_cm, code_verifier):
            raise HTTPException(400, detail='Bad request. code verifier not recognized')

        artifact = self.redis_cache.hget(code, 'arti')
        encrypted_bsn = self.tvs_handler.resolve_artifact(artifact)

        try:
            token_response = current_app.provider.handle_token_request(body.decode('utf-8'),
                                                                    request.headers)

            access_key = base64.b64encode(token_response['id_token'].encode()).decode()
            self.redis_cache.set(access_key, encrypted_bsn)

            json_content_resp = jsonable_encoder(token_response.to_dict())
            return JSONResponse(content=json_content_resp)
        except InvalidClientAuthentication as e:
            current_app.logger.debug('invalid client authentication at token endpoint', exc_info=True)
            error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
            response = Response(error_resp.to_json(), status_code=401)
            response.headers['Content-Type'] = 'application/json'
            response.headers['WWW-Authenticate'] = 'Basic'
            return response
        except OAuthError as e:
            current_app.logger.debug('invalid request: %s', str(e), exc_info=True)
            error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
            response = Response(error_resp.to_json(), status_code=400)
            response.headers['Content-Type'] = 'application/json'
            return response

    async def userinfo_endpoint(self, request: Request):
        current_app  = request.app
        body = await request.body()
        try:
            response = current_app.provider.handle_userinfo_request(body.decode('utf-8'),
                                                                    request.headers)
            json_content = jsonable_encoder(response.to_dict())
            return JSONResponse(content=json_content)
        except (BearerTokenError, InvalidAccessToken) as e:
            error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
            response = Response(error_resp.to_json(), status_code=401)
            response.headers['WWW-Authenticate'] = AccessToken.BEARER_TOKEN_TYPE
            response.headers['Content-Type'] = 'application/json'
            return response
