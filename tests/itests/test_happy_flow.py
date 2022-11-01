import base64
import hashlib
import json
import os
import re
import secrets
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode

import lxml.etree
import lxml.html
import requests
from fastapi.testclient import TestClient
from jwcrypto.jwt import JWT, JWK, JWKSet, JWE
from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey, Box, PublicKey

# Existing max server
# external_test = True
# os.environ.setdefault('REQUESTS_CA_BUNDLE', '/Users/gerbrand/git/github/minvws/nl-rdo-max-private/secrets/ssl/certs/apache-selfsigned.crt')
EXTERNAL_CLIENT_ID = "test_client"

# Testing
EXTENAL_TEST = False

os.environ.setdefault("REQUESTS_CA_BUNDLE", "secrets/cacert.crt")
CLIENT_RSA_PRIV_KEY_PATH = "secrets/clients/test_client/test_client.key"


# pylint:disable=unused-argument
def test_openid_configuration(lazy_app, config, app_mode_default, client):
    app = lazy_app.value
    issuer_url = config["oidc"]["issuer"]
    openid_configuration = app.get(".well-known/openid-configuration").json()
    assert openid_configuration == {
        "version": "3.0",
        "token_endpoint_auth_methods_supported": ["none"],
        "claims_parameter_supported": True,
        "request_parameter_supported": False,
        "request_uri_parameter_supported": True,
        "require_request_uri_registration": False,
        "grant_types_supported": ["authorization_code"],
        "frontchannel_logout_supported": False,
        "frontchannel_logout_session_supported": False,
        "backchannel_logout_supported": False,
        "backchannel_logout_session_supported": False,
        "issuer": issuer_url,
        "authorization_endpoint": issuer_url + "/authorize",
        "jwks_uri": issuer_url + "/jwks",
        "token_endpoint": issuer_url + "/token",
        "scopes_supported": ["openid"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "subject_types_supported": ["pairwise"],
        "userinfo_endpoint": issuer_url + "/userinfo",
        "id_token_signing_alg_values_supported": ["RS256"],
    }


# pylint:disable=unused-argument
def test_legacy_flow(lazy_app, config, app_mode_legacy, legacy_client, pynacl_keys):
    base_uri = config["oidc"]["issuer"]
    app = lazy_app.value
    if EXTENAL_TEST:
        client_id = EXTERNAL_CLIENT_ID
    else:
        client_id = legacy_client[0]

    openid_configuration, access_token_response, _ = base_flow(app, base_uri, client_id)

    validate_legacy_userinfo(
        app, openid_configuration, access_token_response, pynacl_keys
    )


def test_flow(lazy_app, config, app_mode_default, client):
    base_uri = config["oidc"]["issuer"]
    app = lazy_app.value
    if EXTENAL_TEST:
        client_id = EXTERNAL_CLIENT_ID
    else:
        client_id = client[0]

    openid_configuration, access_token_response, jwk_set = base_flow(
        app, base_uri, client_id
    )

    validate_userinfo(app, openid_configuration, access_token_response, jwk_set)


def base_flow(app, base_uri, client_id):
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
    openid_configuration = get_request(
        app, base_uri + "/.well-known/openid-configuration"
    ).json()

    jwk_set = JWKSet.from_json(
        json.dumps(get_request(app, openid_configuration["jwks_uri"]).json())
    )

    authorize_request = fetch_authorize_request(
        app, openid_configuration, code_verifier, client_id
    )

    digid_mock = submit_default_html_form(app, authorize_request, base_uri).text
    authorize_response = submit_default_html_form(app, digid_mock, base_uri).text

    (code, state) = parse_redirect_uri(authorize_response)
    assert base64.b64decode(state).decode("utf-8") == "staat"

    access_token_response = fetch_access_token(
        app, openid_configuration, code_verifier, code, client_id
    )

    validate_access_token_response(access_token_response, jwk_set, base_uri, client_id)
    return openid_configuration, access_token_response, jwk_set


def validate_access_token_response(access_token_response, jwk_set, base_uri, client_id):
    jwt = JWT()
    jwt.deserialize(access_token_response["id_token"], jwk_set)
    claims = json.loads(jwt.claims)
    assert claims["iss"] == base_uri
    assert claims["aud"] == [client_id]
    assert claims["exp"] > int(datetime.now().strftime("%s"))


def fetch_access_token(
    app: TestClient, openid_configuration, code_verifier, code, client_id
):
    query_string = urlencode(
        {
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": "http://localhost:3000/login",
            "code_verifier": code_verifier,
            "client_id": client_id,
        }
    )
    return post_request(
        app, openid_configuration["token_endpoint"], data=query_string
    ).json()


def parse_redirect_uri(authorize_response):
    doc = lxml.html.document_fromstring(authorize_response)
    authorize_redirect_uri = next(doc.iterlinks())[2]
    parsed_url = urlparse(authorize_redirect_uri)
    query = parse_qs(parsed_url.query)
    # noinspection PyTypeChecker
    return query["code"][0], query["state"][0]


def submit_default_html_form(app: TestClient, html, base_uri):
    doc = lxml.html.document_fromstring(html)
    data = {}
    for inp in doc.forms[0].inputs:
        data[inp.name] = inp.value
    if doc.forms[0].method == "POST":
        return post_request(app, base_uri + doc.forms[0].action, data=data)
    return get_request(app, base_uri + doc.forms[0].action, data)


def fetch_authorize_request(
    app: TestClient, openid_configuration, code_verifier, client_id
):
    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")

    authorize_params = {
        "client_id": client_id,
        "scope": "openid",
        "response_type": "code",
        "redirect_uri": "http://localhost:3000/login",
        "state": base64.b64encode("staat".encode("utf-8")),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": secrets.token_urlsafe(),
    }
    return get_request(
        app, openid_configuration["authorization_endpoint"], authorize_params
    ).text


def validate_legacy_userinfo(
    app: TestClient, oidc_configuration, access_token_response, pynacl_keys
):
    userinfo_response = post_request(
        app,
        oidc_configuration["userinfo_endpoint"],
        headers={"Authorization": "Bearer " + access_token_response["id_token"]},
    )

    box = Box(
        PrivateKey(pynacl_keys["client_key"].encode("utf-8"), encoder=Base64Encoder),
        PublicKey(pynacl_keys["server_pub"].encode("utf-8"), encoder=Base64Encoder),
    )
    decrypted = box.decrypt(userinfo_response.text, encoder=Base64Encoder).decode(
        "utf-8"
    )
    assert decrypted == "999991772"


def validate_userinfo(
    app: TestClient, openid_configuration, access_token_response, jwks
):
    userinfo_response = post_request(
        app,
        openid_configuration["userinfo_endpoint"],
        headers={"Authorization": "Bearer " + access_token_response["access_token"]},
    )

    assert userinfo_response.headers["content-type"] == "application/jwt"
    with open(CLIENT_RSA_PRIV_KEY_PATH, "r", encoding="utf-8") as file:
        pem = file.read().encode("utf-8")
    jwe = JWE.from_jose_token(userinfo_response.text)
    jwe.decrypt(JWK.from_pem(pem))
    jwt = JWT()
    jwt.deserialize(jwe.payload.decode("utf-8"), jwks)
    claims = json.loads(jwt.claims)
    assert claims["bsn"] == "999991772"


def get_request(app: TestClient, url: str, params: dict = None, **kwargs):
    if EXTENAL_TEST:
        return requests.get(url, params, timeout=5, **kwargs)
    kwarg = {} if kwargs is None else kwargs
    kwarg["params"] = params
    return app.get(url, **kwarg)


def post_request(app: TestClient, url, data=None, json_data=None, **kwargs):
    if EXTENAL_TEST:
        return requests.post(url, data, json_data, timeout=5, **kwargs)
    return app.post(url, data, json_data, **kwargs)
