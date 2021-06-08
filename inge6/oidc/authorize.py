
from urllib.parse import urlencode, parse_qs

import nacl.hash
from nacl.encoding import URLSafeBase64Encoder

import jwt

from fastapi import  Request, HTTPException
from fastapi.security.utils import get_authorization_scheme_param

from pyop.access_token import AccessToken, BearerTokenError

from .models import AuthorizeRequest
from .oidc import get_oidc_provider
from .cache import redis_cache

def _verify_code_verifier(cc_cm, code_verifier):
    code_challenge_method = cc_cm['code_challenge_method']
    if not code_challenge_method == 'S256':
        return False

    verifier_hash = nacl.hash.sha256(code_verifier.encode('ISO_8859_1'), encoder=URLSafeBase64Encoder)
    code_challenge = verifier_hash.decode().replace('=', '')
    return code_challenge == cc_cm['code_challenge']

def _validate_jwt_token(id_token: str):
    with open('secrets/public.pem') as rsa_priv_key:
        key = rsa_priv_key.read()

    return jwt.decode(id_token, key=key, algorithms=['RS256'], audience=['test_client'])

def assume_authorized(request: Request):
    #Parse JWT token
    authorization: str = request.headers.get("Authorization")
    scheme, id_token = get_authorization_scheme_param(authorization)

    if scheme != 'Bearer' or not _validate_jwt_token(id_token):
        raise HTTPException(status_code=401, detail="Not authorized")

    return True

def authorize(authorization_request: AuthorizeRequest, headers):
    auth_req = get_oidc_provider().parse_authentication_request(urlencode(authorization_request.dict()), headers)
    return auth_req

def accesstoken(provider, request_body, headers):
    code = parse_qs(request_body.decode())['code'][0]
    code_verifier = parse_qs(request_body.decode())['code_verifier'][0]

    cc_cm = redis_cache.hget(code, 'cc_cm')

    if not _verify_code_verifier(cc_cm, code_verifier):
        raise HTTPException(400, detail='Bad request. code verifier not recognized')

    token_response = provider.handle_token_request(request_body.decode('utf-8'), headers)
    return token_response