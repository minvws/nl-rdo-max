import base64
import hashlib
import json
import os
import re
import secrets
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from typing import Union

import lxml.html
import pytest
import requests
from fastapi.testclient import TestClient
from jwcrypto.jwt import JWT, JWKSet, JWE

# Existing max server
# todo fix this tests?

os.environ.setdefault("REQUESTS_CA_BUNDLE", "secrets/cacert.crt")
# os.environ.setdefault("REQUESTS_CA_BUNDLE", "secrets/cacert.crt")


@pytest.mark.skip(reason="Run this only with a local running max instance")
def test_external_application(test_client_id):
    base_uri = "https://localhost:8006"

    base_flow(app=None, base_uri=base_uri, client_id=test_client_id)


def test_flow(
    lazy_app,
    config_with_cc_userinfo_service,
    test_client_without_client_auth_id,
    lazy_container,
    redis,
    test_client_without_client_auth_private_key,
):
    base_uri = config_with_cc_userinfo_service["oidc"]["issuer"]
    app = lazy_app.value
    redis.set("max:primary_identity_provider", "tvs")

    openid_configuration, access_token_response, jwk_set = base_flow(
        app, base_uri, test_client_without_client_auth_id
    )
    validate_userinfo(
        app,
        openid_configuration,
        access_token_response,
        jwk_set,
        test_client_without_client_auth_private_key,
    )


def base_flow(app: Union[None, TestClient], base_uri, client_id):
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
    code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)
    oidc_configuration = get_request(
        app, base_uri + "/.well-known/openid-configuration"
    ).json()

    jwk_set = JWKSet.from_json(
        json.dumps(get_request(app, oidc_configuration["jwks_uri"]).json())
    )
    authorize_request = fetch_authorize_request(
        app, oidc_configuration, code_verifier, client_id
    )

    digid_mock = submit_default_html_form(app, authorize_request, base_uri).text
    authorize_response = submit_default_html_form(app, digid_mock, base_uri).text

    (code, state) = parse_redirect_uri(authorize_response)
    assert base64.b64decode(state).decode("utf-8") == "staat"

    access_token_response = fetch_access_token(
        app, oidc_configuration, code_verifier, code, client_id
    )

    validate_access_token_response(access_token_response, jwk_set, base_uri, client_id)
    return oidc_configuration, access_token_response, jwk_set


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
        return post_request(app, base_uri + "/" + doc.forms[0].action, data=data)
    return get_request(app, base_uri + "/" + doc.forms[0].action, data)


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
        "state": base64.b64encode("staat".encode("utf-8")).decode("utf-8"),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": secrets.token_urlsafe(),
        "login_hint": "digid_mock",
    }
    return get_request(
        app, openid_configuration["authorization_endpoint"], authorize_params
    ).text


def validate_userinfo(
    app: TestClient,
    oidc_configuration,
    access_token_response,
    jwks,
    test_client_private_key,
):
    userinfo_response = post_request(
        app,
        oidc_configuration["userinfo_endpoint"],
        headers={"Authorization": "Bearer " + access_token_response["access_token"]},
    )

    assert userinfo_response.headers["content-type"] == "application/jwt"
    assert userinfo_response.headers["authentication-method"] == "digid_mock"
    jwe = JWE.from_jose_token(userinfo_response.text)
    jwe.decrypt(test_client_private_key)
    jwt = JWT()
    jwt.deserialize(jwe.payload.decode("utf-8"), jwks)
    claims = json.loads(jwt.claims)
    assert claims["bsn"] == "999991772"


def get_request(app: Union[None, TestClient], url: str, params: dict = None, **kwargs):
    if app is None:
        return requests.get(url, params, timeout=5, **kwargs)
    kwarg = {} if kwargs is None else kwargs
    kwarg["params"] = params
    return app.get(url, **kwarg)


def post_request(
    app: Union[None, TestClient], url, data=None, json_data=None, **kwargs
):
    if app is None:
        return requests.post(url, data, json_data, timeout=5, **kwargs)
    return app.post(url, data=data, json=json_data, **kwargs)
