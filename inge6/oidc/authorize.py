from typing import Tuple, Dict, List, Text
from urllib.parse import parse_qs

import nacl.hash
from nacl.encoding import URLSafeBase64Encoder

import jwt

from fastapi import  Request, HTTPException
from fastapi.security.utils import get_authorization_scheme_param

from ..cache import redis_cache

def _compute_code_challenge(code_verifier: str):
    """
    Given a code verifier compute the code_challenge. This code_challenge is computed as defined (https://datatracker.ietf.org/doc/html/rfc7636#section-4.2):

        code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))).

    This shows that the SHA256 of the ascii encoded code_verifier is URLSafe base64 encoded. We have adjusted the encoding to the ISO_8859_1 encoding,
    conform to the AppAuth SDK for Android and IOS. Moreover, we remove the base64 padding (=).

    :param code_verifier: the code verifier to transform to the Code Challenge
    """
    verifier_hash = nacl.hash.sha256(code_verifier.encode('ISO_8859_1'), encoder=URLSafeBase64Encoder)
    return verifier_hash.decode().replace('=', '')

def verify_code_verifier(cc_cm: Dict[str ,str], code_verifier: str) -> bool:
    """
    Verify that the given code_verifier complies with the initially supplied code_challenge.

    Only supports the SHA256 code challenge method, plaintext is regarded as unsafe.

    :param cc_cm: the initially supplied Code Challenge Code challenge Method dictionary
    :param code_verifier: the code_verfier to check against the code challenge.
    :returns: whether the code_verifier is what was expected given the cc_cm
    """
    code_challenge_method = cc_cm['code_challenge_method']
    if not code_challenge_method == 'S256':
        return False

    code_challenge = _compute_code_challenge(code_verifier)
    return code_challenge == cc_cm['code_challenge']


def validate_jwt_token(key: str, id_token: str, audience: List[Text]) -> dict:
    """
    Verify and decode the JWT Token, raises exception on error.

    :param key: the key used to validate the id_token
    :param id_token: the JWT Token granting access to our services
    :returns: a dictionary containing the parts of the valid JWT token
    :raises InvalidSignatureError: raises an exception when the id_token is invalid.
    """
    return jwt.decode(id_token, key=key, algorithms=['RS256'], audience=audience)


def is_authorized(key: str, request: Request, audience: List[Text]) -> Tuple[str, str]:
    """
    Verify that a request is authorized by verifying the id_token in the Authorization
    header.

    :param key: the key used to validate the JWT token contained in the request param
    :param request: the request containing the authorization header that should contain a bearer token
    :returns: the validated id_token and a hash of the id_token
    :raises InvalidSignatureError: raises an exception when the id_token is invalid.
    """
    authorization: str = request.headers.get("Authorization")
    scheme, id_token = get_authorization_scheme_param(authorization)

    if scheme != 'Bearer':
        raise HTTPException(status_code=401, detail="Not authorized")

    jwt_dict = validate_jwt_token(key, id_token, audience)
    return id_token, jwt_dict['at_hash']

def _is_valid_at_request_body(request_body: bytes):
    """
    Is the request body valid. i.e. does it contain the code and code_verifier parameter as expected

    :param request_body: the bytes encoded body of the request
    :returns: the urlencoded body as dictionary. Where the keys are the parameter names, and the values are list of values
    :raises ValueError: raises error when the expected parameters are not present.
    """
    parsed_request_body = parse_qs(request_body.decode())
    expected_params = ['code', 'code_verifier']

    if not all(x in parsed_request_body for x in expected_params):
        raise ValueError("Expects `code` and `code_verifier` to be contained in the urlencoded body of the request")

    return parsed_request_body

def accesstoken(provider, request_body, headers):
    """
    An access token is requested through this function. It validates whether the body contains the expected parameters and verifies the
    supplied code_verifier.

    :param provider: the provider that is eventually allow to handle the token request once the validations have been performed
    :param request_body: the body containing, among others, the code and code_verifier parameter
    :param headers: the headers needed for the token request
    :returns: an accesstoken is returned on success. This means that the code_verifier was verified correctly, and the parameters contain what was expected
    :raises HTTPException: raises a 400 exception when the request is invalid
    """
    try:
        parsed_request_body = _is_valid_at_request_body(request_body)
    except ValueError as parse_error:
        raise HTTPException(400, detail=str(parse_error)) from parse_error

    code = parsed_request_body['code'][0]
    code_verifier = parsed_request_body['code_verifier'][0]

    cc_cm = redis_cache.hget(code, 'cc_cm')

    if cc_cm is None:
        raise HTTPException(400, detail='Code challenge has expired. Please retry authorization.')

    if not verify_code_verifier(cc_cm, code_verifier):
        raise HTTPException(400, detail='Bad request. code verifier not recognized')

    token_response = provider.handle_token_request(request_body.decode('utf-8'), headers)
    return token_response
