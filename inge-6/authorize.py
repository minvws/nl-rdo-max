from urllib.parse import parse_qs, urlparse

from typing import Dict
import base64
import json
from urllib.parse import urlencode, quote_plus

from fastapi import  Request, Response
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

         # parse authentication request
        current_app = request.app
        body = request.query_params
        try:
            auth_req = current_app.provider.parse_authentication_request(urlencode(body), request.headers)

            # TODO: Custom implement?
            code_challenge = body['code_challenge']
            code_challenge_method = body['code_challenge_method']
        except InvalidAuthenticationRequest as e:
            current_app.logger.debug('received invalid authn request', exc_info=True)
            error_url = e.to_error_url()
            if error_url:
                return RedirectResponse(error_url, status_code=303)
            else:
                # show error to user
                return Response(content='Something went wrong: {}'.format(str(e)), status_code=400)

        # automagic authentication
        authn_response = current_app.provider.authorize(auth_req, 'test_user')
        response_url = authn_response.request('/digid-mock', False)
        redirect_uri = auth_req['redirect_uri']
        state = request.query_params['state']

        return RedirectResponse(response_url + f"&redirect_uri={redirect_uri}&state={state}", status_code=303)

    async def token_endpoint(self, request):
        current_app = request.app
        body = await request.body()
        code = parse_qs(body.decode())['code'][0]
        bsn = self.redis_cache.get(code)

        try:
            token_response = current_app.provider.handle_token_request(body.decode('utf-8'),
                                                                    request.headers)

            # token_base64_dump = base64.b64encode(json.dumps(token_response.to_dict()).encode()).decode()
            print('EXPECTED KEY: ', token_response['id_token'])
            self.redis_cache.set(token_response['id_token'], bsn)

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
