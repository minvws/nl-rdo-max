import json
import re

import uuid
import urllib.parse as urlparse
from unittest.mock import MagicMock
import pytest
import packaging

from freezegun import freeze_time

from starlette.datastructures import Headers
from starlette.requests import Request

from pydantic.error_wrappers import ValidationError

from fastapi import HTTPException

from inge6.saml.constants import NAMESPACES
from inge6.saml.utils import get_referred_node
from inge6.saml.exceptions import UserNotAuthenticated

from inge6.exceptions import ExpectedRedisValue
from inge6 import constants
from inge6.provider import Provider, _get_bsn_from_art_resp
from inge6.models import AuthorizeRequest, SorryPageRequest
from inge6.config import get_settings
from inge6.router import consume_bsn_for_token

from ..resources.utils import PRIV_KEY_BSN_AES_KEY

def test_sorry_too_busy(mock_provider: Provider):
    request = SorryPageRequest(
        state = "state",
        redirect_uri = "uri",
        client_id = "test_client"
    )


    response = mock_provider.sorry_something_went_wrong(request)
    assert "Het is erg druk op dit moment, iets te druk zelfs." in response.body.decode()

# pylint: disable=unused-argument
def test_get_bsn_from_artresponse(mock_provider):
    art_resp_sector = 's00000000:900029365'
    provider = mock_provider
    id_provider = provider.get_id_provider('tvs')
    original_version = id_provider.saml_spec_version
    id_provider.saml_spec_version = packaging.version.Version("3.5")
    assert _get_bsn_from_art_resp(art_resp_sector, id_provider) == '900029365' # pylint: disable=protected-access
    id_provider.saml_spec_version = original_version


def test_authorize_ratelimit(mocker, mock_provider, fake_redis_user_limit_key, digid_mock_disable):
    redis_cache = mock_provider.redis_cache
    redis_mock = redis_cache.redis_client

    redis_mock.set('tvs:primary_idp', 'digid')
    redis_mock.set('user_limit_key', 3)

    provider = mock_provider
    mocker.patch.object(provider, 'redis_cache',  redis_cache)

    authorize_params = {
        'client_id': "test_client",
        'redirect_uri': "http://localhost:3000/login",
        'response_type': "code",
        'nonce': "n-0S6_WzA2Mj",
        'state': "af0ifjsldkj",
        'scope': "openid",
        'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        'code_challenge_method': "S256",
    }

    headers: Headers = Headers({})
    auth_req = AuthorizeRequest(**authorize_params)

    # First three calls no problem
    resp = provider.authorize_endpoint(auth_req, headers, '0.0.0.1')
    assert not ('location' in resp.headers and resp.headers['location'].startswith('/sorry-something-went-wrong'))
    resp = provider.authorize_endpoint(auth_req, headers, '0.0.0.2')
    assert not ('location' in resp.headers and resp.headers['location'].startswith('/sorry-something-went-wrong'))
    resp = provider.authorize_endpoint(auth_req, headers, '0.0.0.3')
    assert not ('location' in resp.headers and resp.headers['location'].startswith('/sorry-something-went-wrong'))

    # Fourth is the limit.
    resp = provider.authorize_endpoint(auth_req, headers, '0.0.0.4')
    assert resp.headers['location'].startswith('/sorry-something-went-wrong')


def test_authorize_invalid_model():
    authorize_params = {
        'client_id': "test_client",
        'redirect_uri': "http://localhost:3000/login",
        'response_type': "id_token",
        'nonce': "n-0S6_WzA2Mj",
        'state': "af0ifjsldkj",
        'scope': "openid",
        'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        'code_challenge_method': "S256",
    }

    with pytest.raises(ValidationError):
        AuthorizeRequest(**authorize_params)

def test_authorize_invalid_request(digid_mock_disable, redis_mock, digid_config, mock_provider): # pylint: disable=unused-argument

    authorize_params = {
        'client_id': "some_unknown_client",
        'redirect_uri': "http://localhost:3000/login",
        'response_type': "code",
        'nonce': "n-0S6_WzA2Mj",
        'state': "af0ifjsldkj",
        'scope': "openid",
        'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        'code_challenge_method': "S256",
    }

    headers: Headers = Headers({})
    auth_req = AuthorizeRequest(**authorize_params)
    resp = mock_provider.authorize_endpoint(auth_req, headers, '0.0.0.0')
    assert resp.status_code == 303
    assert "error=unauthorized_client" in resp.headers['location']
    assert "error_message=Unknown+client_id" in resp.headers['location']
    assert f"state={authorize_params['state']}" in resp.headers['location']

# pylint: disable=unused-argument
def test_expected_redis_primary_idp(redis_mock, mock_provider):
    redis_mock.delete(get_settings().primary_idp_key)

    authorize_params = {
        'client_id': "some_unknown_client",
        'redirect_uri': "http://localhost:3000/login",
        'response_type': "code",
        'nonce': "n-0S6_WzA2Mj",
        'state': "af0ifjsldkj",
        'scope': "openid",
        'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        'code_challenge_method': "S256",
    }

    headers: Headers = Headers({})
    auth_req = AuthorizeRequest(**authorize_params)

    with pytest.raises(ExpectedRedisValue):
        mock_provider.authorize_endpoint(auth_req, headers, '0.0.0.0')

# pylint: disable=unused-argument
def mock_verify_signatures(tree, cert_data):
    signature_nodes = tree.findall('.//dsig:Signature', NAMESPACES)
    return get_referred_node(tree, signature_nodes[0])

def mock_symm_encrypt(bsn):
    return bsn

@freeze_time("2021-06-01 12:44:06")
def test_resolve_artifact_tvs(requests_mock, mocker, redis_mock, tvs_config, mock_provider): # pylint: disable=unused-argument
    provider = mock_provider
    id_provider = provider.get_id_provider('tvs')

    # Allow the decryption of the BSN using a custom privkey, and force the key name used along with that privkey
    mocker.patch.object(id_provider, 'priv_key', PRIV_KEY_BSN_AES_KEY)
    mocker.patch.object(id_provider.sp_metadata, 'dv_keynames', ['70c7065d4ad1bec9f57e4bd3dfd6812af6035d57e1ec3496b600491d8c238081'])

    # Do not re-encrypt, not the purpose of this test
    mocker.patch.object(provider.bsn_encrypt, 'symm_encrypt', mock_symm_encrypt)

    # Do not verify signature, something we cannot do in development envs for this artifact_response
    mocker.patch('inge6.saml.artifact_response.verify_signatures', mock_verify_signatures)

    # Setup mocking endpoint
    with open('tests/resources/sample_messages/artifact_response_custom_bsn.xml', 'r', encoding='utf-8') as art_resp_file:
        artifact_resolve_response = art_resp_file.read()

    artifact_resolve_url = id_provider.idp_metadata.get_artifact_rs()['location']
    requests_mock.post(artifact_resolve_url, text=artifact_resolve_response)

    # pylint: disable=protected-access
    bsn = provider._resolve_artifact('XXX', 'tvs')
    assert bsn == '900212640'

def test_assertion_consumer_service(digid_config, digid_mock_disable, mock_provider):
    provider: Provider = mock_provider
    redis_mock = provider.redis_client
    redis_cache = provider.redis_cache
    settings = provider.settings

    code_challenge = "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw"
    auth_req = AuthorizeRequest(
        code_challenge_method="S256",
        client_id="test_client",
        redirect_uri="http://localhost:3000/login",
        response_type="code",
        nonce="n-0S6_WzA2Mj",
        state="af0ifjsldkj",
        scope="openid",
        code_challenge=code_challenge # code_verifier = SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
    )

    headers = Headers()
    response = provider.authorize_endpoint(auth_req, headers, '0.0.0.0')
    redirect_url = response.headers.get('location')

    parsed_url = urlparse.urlparse(redirect_url)
    query_params = urlparse.parse_qs(parsed_url.query)
    relay_state = query_params.get("RelayState")[0]
    artifact = str(uuid.uuid4())
     # pylint: disable=too-few-public-methods
    class DummyRequest():
        query_params = {
            "RelayState": relay_state,
            "SAMLart": artifact
        }
    acs_resp = provider.assertion_consumer_service(DummyRequest())

    redirect_url = re.search(r"<meta http-equiv=\"refresh\" content=\"0;url=(.*?)\" />", acs_resp.body.decode())
    parsed_url = urlparse.urlparse(redirect_url[1])
    query_params = urlparse.parse_qs(parsed_url.query)
    expected_code = query_params['code'][0]

    # Grabbing the generated code from redis, this could be cleaner / better
    items = redis_mock.scan(0)[1]
    code = None
    for item in items:
        item = item.decode("utf-8")
        temp_code = item[len(settings.redis.default_cache_namespace):].replace(":", "")
        if settings.redis.default_cache_namespace in item and len(temp_code) == 32:
            code = temp_code
            break

    assert code == expected_code
    artifact_redis = redis_cache.hget(code, constants.RedisKeys.ARTI.value)
    assert artifact_redis
    assert artifact_redis.get("artifact", artifact)
    assert artifact_redis.get("id_provider", 'digid')

    code_challenge_redis = redis_cache.hget(code, constants.RedisKeys.CC_CM.value)
    assert code_challenge_redis
    assert code_challenge_redis.get("code_challenge") == code_challenge
    assert code_challenge_redis.get("code_challenge_method") == "S256"

    # Test if time to life / expiry is set correctly on the Redis namespace
    # pylint: disable=protected-access
    assert _approx_eq(redis_mock.ttl(redis_cache._get_namespace(code)), int(settings.redis.object_ttl), 5)

def _approx_eq(dynam_val: int, stat_val: int, delta: int):
    return dynam_val >= stat_val - delta or dynam_val <= stat_val + delta

# pylint: disable=unused-argument
def mock_is_authorized(key, request, audience):
    return "", "mocking_the_at_hash_XYZ"

def test_accesstoken_fail_userlogin(mock_clients_db, redis_mock, tvs_config, mocker, digid_mock_disable, mock_provider):
    # pylint: disable=unused-argument
    def raise_user_login_failed(*args, **kwargs):
        raise UserNotAuthenticated("User authentication flow failed", oauth_error='saml_authn_failed')

    class TMPRequest(Request):
        def __init__(self, headers):
            self.scope = {
                "type": "http",
                'client': ('0.0.0.0', '0000')
            }
            self._headers = headers
            super().__init__(self.scope)

        @property
        def app(self):
            mock_app = MagicMock()
            mock_app.state.provider = mock_provider
            return mock_app

    mocker.patch.object(mock_provider, '_resolve_artifact', raise_user_login_failed)

    headers: Headers = Headers({})
    request = TMPRequest(headers)

    redirect_uri = "http://localhost:3000/login"
    client_id = 'test_client'
    bsn = '999991772'

    authorize_params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': "code",
        'nonce': "n-0S6_WzA2Mj",
        'state': "af0ifjsldkj",
        'scope': "openid",
        'code_challenge': "_1f8tFjAtu6D1Df-GOyDPoMjCJdEvaSWsnqR6SLpzsw", # code_verifier : SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c
        'code_challenge_method': "S256",
    }

    auth_req = AuthorizeRequest(**authorize_params)
    resp = consume_bsn_for_token(bsn, request, auth_req)
    assert resp.status_code == 200

    code = json.loads(resp.body)['code'][0]
    code_verifier = 'SoOEDN-mZKNhw7Mc52VXxyiqTvFB3mod36MwPru253c'

    acc_req_body = f'client_id={client_id}&redirect_uri={redirect_uri}&code={code}&code_verifier={code_verifier}&grant_type=authorization_code'

    accesstoken_resp = mock_provider.token_endpoint(acc_req_body.encode(), headers)
    assert accesstoken_resp.status_code == 400
    assert json.loads(accesstoken_resp.body.decode()) == {
        'error': 'saml_authn_failed',
        'error_description': 'User authentication flow failed'
    }

# pytest: disable=unused-argument
def test_bsn_attribute(mocker, redis_cache, mock_provider):
    provider = mock_provider

    mocker.patch('inge6.provider.is_authorized', mock_is_authorized)
    mocker.patch.object(provider, 'redis_cache', redis_cache)

    bsn = "123456789"
    encrypted_bsn_object = provider.bsn_encrypt.symm_encrypt(bsn)
    mocker.patch.object(provider.bsn_encrypt, 'from_symm_to_pub', provider.bsn_encrypt.symm_decrypt)
    redis_cache.set("mocking_the_at_hash_XYZ", encrypted_bsn_object)

    request = Request({'type': 'http'})
    resp = provider.bsn_attribute(request)
    assert resp.status_code == 200
    assert resp.body.decode() == bsn


# pytest: disable=unused-argument
def test_bsn_attribute_no_value(mocker, mock_provider):
    mocker.patch('inge6.provider.is_authorized', mock_is_authorized)

    provider = mock_provider
    request = Request({'type': 'http'})
    with pytest.raises(HTTPException) as http_exc:
        provider.bsn_attribute(request)

    assert http_exc.value.status_code == 408
    assert http_exc.value.detail == "Resource expired.Try again after /authorize"


def test_metadata(mock_provider):
    provider = mock_provider

    resp = provider.metadata('digid')
    assert resp.status_code == 200
    assert resp.media_type == 'application/xml'

    resp = provider.metadata('tvs')
    assert resp.status_code == 200
    assert resp.media_type == 'application/xml'



def test_metadata_unknown_id_provider(mock_provider):
    provider = mock_provider

    with pytest.raises(HTTPException) as http_exc:
        provider.metadata('AAAAAAAAAA_dont-exist')

    assert http_exc.value.status_code == 404
    assert http_exc.value.detail == "Page not found"


def test_metadata_invalid(mocker, mock_provider):
    provider = mock_provider
    id_provider = provider.get_id_provider('digid')

    mocker.patch.object(id_provider.sp_metadata, 'validate', lambda: ["this is an error"])
    with pytest.raises(HTTPException) as http_exc:
        provider.metadata('digid')

    assert http_exc.value.status_code == 500
    assert http_exc.value.detail == "this is an error"
