
from urllib.parse import parse_qs

import nacl.hash
from nacl.encoding import URLSafeBase64Encoder

import jwt

from fastapi import  Request, HTTPException
from fastapi.security.utils import get_authorization_scheme_param

from ..models import AuthorizeRequest
from ..cache import redis_cache

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

def is_authorized(request: Request):
    #Parse JWT token
    authorization: str = request.headers.get("Authorization")
    scheme, id_token = get_authorization_scheme_param(authorization)

    jwt_dict = _validate_jwt_token(id_token)
    if scheme != 'Bearer' or not jwt_dict:
        raise HTTPException(status_code=401, detail="Not authorized")

    return id_token, jwt_dict['at_hash']

# def authorize(provider, authorization_request: AuthorizeRequest, headers):
#     auth_req =
#     return auth_req

def accesstoken(provider, request_body, headers):
    code = parse_qs(request_body.decode())['code'][0]
    code_verifier = parse_qs(request_body.decode())['code_verifier'][0]

    cc_cm = redis_cache.hget(code, 'cc_cm')

    if not _verify_code_verifier(cc_cm, code_verifier):
        raise HTTPException(400, detail='Bad request. code verifier not recognized')

    token_response = provider.handle_token_request(request_body.decode('utf-8'), headers)
    return token_response