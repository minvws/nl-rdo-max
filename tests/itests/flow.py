import requests
import os
import base64
import re
import hashlib
import secrets
import json
import lxml.html
import lxml.etree
from urllib.parse import urlparse, parse_qs, urlencode
from jwcrypto.jwt import JWT, JWK, JWKSet, JWE
from datetime import datetime


os.environ.setdefault('REQUESTS_CA_BUNDLE', 'secrets/cacert.crt')


def test_flow():
    openid_configuration = requests.get('https://localhost:8006/.well-known/openid-configuration').json()
    jwks = requests.get(openid_configuration['jwks_uri']).json()

    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    client_id = '37692967-0a74-4e91-85ec-a4250e7ad5e8'
    authorize_params = {
        'client_id': client_id,
        'scope': 'openid',
        'response_type': 'code',
        'redirect_uri': 'http://localhost:3000/login',
        'state': base64.b64encode('staat'.encode('utf-8')),
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'nonce': secrets.token_urlsafe()
    }

    authorize_request = requests.get(openid_configuration['authorization_endpoint'], authorize_params).text
    doc = lxml.html.document_fromstring(authorize_request)
    post_data = {}
    for e in doc.forms[0].inputs:
        post_data[e.name] = e.value
    digid_mock = requests.post("https://localhost:8006" + doc.forms[0].action, data=post_data).text
    doc = lxml.html.document_fromstring(digid_mock)
    get_args = {}
    for e in doc.forms[0].inputs:
        get_args[e.name] = e.value
    authorize_response = requests.get("https://localhost:8006" + doc.forms[0].action, get_args).text
    doc = lxml.html.document_fromstring(authorize_response)
    authorize_redirect_uri = next(doc.iterlinks())[2]
    parsed_url = urlparse(authorize_redirect_uri)
    query = parse_qs(parsed_url.query)
    code = query['code'][0]
    state = query['state'][0]
    assert base64.b64decode(state).decode('utf-8') == 'staat'
    requests.get(openid_configuration['token_endpoint'])
    query_string = urlencode({
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': 'http://localhost:3000/login',
        'code_verifier': code_verifier,
        'client_id': client_id
    })
    access_token_response = requests.post(openid_configuration['token_endpoint'], data=query_string).json()
    jwk_set = JWKSet.from_json(json.dumps(requests.get(openid_configuration['jwks_uri']).json()))
    jwt = JWT()
    jwt.deserialize(access_token_response['id_token'], jwk_set)
    claims = json.loads(jwt.claims)

    assert claims['iss'] == "https://localhost:8006"
    assert claims['aud'] == [client_id]
    assert claims['exp'] > int(datetime.now().strftime('%s'))

    userinfo_response = requests.get(openid_configuration['userinfo_endpoint'], headers={'Authorization': 'Bearer ' + access_token_response['access_token']})
    assert userinfo_response.headers['content-type'] == 'application/jwt'
    with open('secrets/clients/test_client/test_client.key', 'r', encoding='utf-8') as file:
        pem = file.read().encode('utf-8')
    jw = JWE()
    jw.deserialize(userinfo_response.text, JWK.from_pem(pem))
    jwt.deserialize(jw.payload.decode('utf-8'), jwk_set)
    claims = json.loads(jwt.claims)
    print(claims)
    assert claims['givenName'] == 'givenName'

