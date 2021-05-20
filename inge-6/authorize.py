from typing import Dict
from urllib.parse import urlencode

from fastapi import  Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.encoders import jsonable_encoder

from oic.oic.message import TokenErrorResponse, UserInfoErrorResponse
from pyop.access_token import AccessToken, BearerTokenError
from pyop.exceptions import InvalidAuthenticationRequest, InvalidAccessToken, InvalidClientAuthentication, OAuthError

class AuthorizationHandler:

    def authorize(self, request: Request):
         # parse authentication request
        current_app = request.app
        body = request.query_params
        try:
            auth_req = current_app.provider.parse_authentication_request(urlencode(body), request.headers)
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
        # response_url = authn_response.request(auth_req['redirect_uri'], False)
        request.session['redirect-uri'] = auth_req['redirect_uri']
        response_url = authn_response.request('/login-digid', False)

        # SAML authorization, link to id_token in redis-cache
        return RedirectResponse(response_url, status_code=303)

    async def token_endpoint(self, request: Request):
        current_app = request.app
        body = await request.body()
        try:
            token_response = current_app.provider.handle_token_request(body.decode('utf-8'),
                                                                    request.headers)
            json_content = jsonable_encoder(token_response.to_dict())
            return JSONResponse(content=json_content)
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