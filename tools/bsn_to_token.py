import sys
import uuid
import json
import logging
import requests
import argparse

import nacl.hash
from nacl.encoding import URLSafeBase64Encoder

DEFAULT_SERVER_HOST = "https://tvs-connect.acc.coronacheck.nl"
DEFAULT_SERVER_PORT = 443

DEFAULT_CLIENT_ID = 'test_client'


def randstr():
    return uuid.uuid4().hex


def compute_code_challenge(code_verifier):
    verifier_hash = nacl.hash.sha256(code_verifier.encode('ISO_8859_1'), encoder=URLSafeBase64Encoder)
    code_challenge = verifier_hash.decode().replace('=', '')
    return code_challenge


def retrieve_token(base_url, bsn):
    print(bsn)
    nonce = randstr()
    state = randstr()

    code_verifier = randstr()
    code_challenge = compute_code_challenge(code_verifier)

    redirect_rui = 'http://157.90.231.134:3000/login'

    params = {
        'client_id': args.client_id,
        'response_type': 'code',
        'redirect_uri': redirect_rui,
        'scope': 'openid',
        'nonce': nonce,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    auth_url = f'{base_url}/consume_bsn/{bsn}'

    code_state_resp = requests.get(auth_url, params=params, verify=False)
    code_state_dict = json.loads(code_state_resp.text)

    code = code_state_dict['code'][0]
    state = code_state_dict['state'][0]
    data = f"client_id={args.client_id}&code={code}&state={state}&code_verifier={code_verifier}&" \
           f"grant_type=authorization_code&redirect_uri={redirect_rui}"
    at_url = f'{base_url}/accesstoken'

    accesstoken = requests.post(url=at_url, data=data)
    id_token = json.loads(accesstoken.text)['id_token']
    return id_token


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert a BSN to JWT Token tool.")
    parser.add_argument("--server-host", type=str, nargs='?', default=DEFAULT_SERVER_HOST,
                        help="Server host to request JWT token from")
    parser.add_argument("--server-port", type=int, nargs='?', default=DEFAULT_SERVER_PORT,
                        help="Server port to request JWT token from")
    parser.add_argument("--client-id", type=str, nargs='?', default=DEFAULT_CLIENT_ID,
                        help="Client ID to request JWT token from")
    args = parser.parse_args()

    server_host: str = args.server_host
    server_port: int = args.server_port


    base_url = f'{server_host}:{server_port}'
    for inline in sys.stdin:
        bsn = inline.replace('\n', '')
        id_token = retrieve_token(base_url, bsn)
        print(id_token)
